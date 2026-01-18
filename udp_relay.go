package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// Wire examples show 4B 57 which is ASCII "KW".
	// Doc text says 0x574B ("WK") but dumps indicate "KW".
	// This code follows the dumps: magic = 'K','W'.
	magic0 = byte('K')
	magic1 = byte('W')

	version = 0x02

	typeHello  = 0x01
	typeAudio  = 0x02
	typeBye    = 0x03
	typeStatus = 0x04

	// NOTE: Your new spec reserves bits 1-7, but we keep VIA_RELAY in bit 1.
	// Remove if you don't want the relay to mutate flags.
	flagViaRelay = 1 << 1

	headerLen    = 36
	authOffset   = 20
	authLen      = 16
	audioHdrLen  = 2
	maxAudioData = 800

	statusPayloadLen = 2 // uint16 peer count
)

var relayDeviceID = deviceID{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

type deviceID [6]byte

type peer struct {
	addr     *net.UDPAddr
	lastSeen time.Time

	// Token bucket limiter (per device).
	tokens     float64
	lastRefill time.Time

	// Dirty flag: peer needs STATUS update on next HELLO.
	stateDirty bool
}

type config struct {
	listenAddr     string
	key            []byte
	peerTimeout    time.Duration
	cleanupEvery   time.Duration
	rateLimitPPS   float64
	rateLimitBurst float64
	metricsAddr    string
}

type metrics struct {
	started time.Time

	recvTotal      uint64
	fwdTotal       uint64
	dropBadLen     uint64
	dropBadMagic   uint64
	dropBadVersion uint64
	dropBadType    uint64
	dropBadAudio   uint64
	dropBadMAC     uint64
	dropRateLimit  uint64

	peersCurrent int64
	peersAdded   uint64
	peersExpired uint64
}

type relay struct {
	cfg config
	m   metrics

	mu    sync.RWMutex
	peers map[deviceID]*peer

	// Relay's own sequence counter for STATUS packets.
	seq uint32

	// Buffers reused to avoid per-packet allocations.
	readBuf    []byte
	forwardBuf []byte
	statusBuf  []byte

	// Reusable HMAC object (receive loop is single-threaded).
	hmacObj hashHash
}

type hashHash interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
	Reset()
}

func parseKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasPrefix(s, "hex:"):
		return hex.DecodeString(strings.TrimPrefix(s, "hex:"))
	case strings.HasPrefix(s, "b64:"):
		return base64.StdEncoding.DecodeString(strings.TrimPrefix(s, "b64:"))
	default:
		if len(s) < 16 {
			return nil, fmt.Errorf("key too short; use hex: or b64: with at least 16 bytes")
		}
		return []byte(s), nil
	}
}

func newRelay(cfg config) *relay {
	r := &relay{
		cfg:        cfg,
		peers:      make(map[deviceID]*peer),
		readBuf:    make([]byte, 2048),
		forwardBuf: make([]byte, 2048),
		statusBuf:  make([]byte, headerLen+statusPayloadLen),
	}
	r.m.started = time.Now()
	r.hmacObj = hmac.New(sha256.New, r.cfg.key)
	return r
}

func (r *relay) computeMAC128(pkt []byte, out *[authLen]byte) {
	// pkt must have auth_tag bytes zeroed already.
	r.hmacObj.Reset()
	_, _ = r.hmacObj.Write(pkt)
	sum := r.hmacObj.Sum(nil)
	copy(out[:], sum[:authLen])
}

func (r *relay) verifyMAC(pkt []byte) bool {
	// Save auth_tag
	var got [authLen]byte
	copy(got[:], pkt[authOffset:authOffset+authLen])

	// Zero auth_tag in-place, compute, then restore.
	for i := 0; i < authLen; i++ {
		pkt[authOffset+i] = 0
	}
	var exp [authLen]byte
	r.computeMAC128(pkt, &exp)
	copy(pkt[authOffset:authOffset+authLen], got[:])

	return hmac.Equal(got[:], exp[:])
}

func (r *relay) signInPlace(pkt []byte) {
	// Zero auth_tag, compute HMAC, write tag.
	for i := 0; i < authLen; i++ {
		pkt[authOffset+i] = 0
	}
	var tag [authLen]byte
	r.computeMAC128(pkt, &tag)
	copy(pkt[authOffset:authOffset+authLen], tag[:])
}

func parseDeviceID(pkt []byte) deviceID {
	var id deviceID
	copy(id[:], pkt[4:10])
	return id
}

func (r *relay) buildStatusPacket(peerCount uint16) []byte {
	pkt := r.statusBuf

	// Header
	pkt[0] = magic0
	pkt[1] = magic1
	pkt[2] = version
	pkt[3] = typeStatus
	copy(pkt[4:10], relayDeviceID[:])
	r.seq++
	binary.LittleEndian.PutUint32(pkt[10:14], r.seq)
	// Timestamp (bytes 14-17): 0
	pkt[14], pkt[15], pkt[16], pkt[17] = 0, 0, 0, 0
	// Flags (byte 18): 0
	pkt[18] = 0
	// Reserved (byte 19): 0
	pkt[19] = 0
	// Auth tag will be filled by signInPlace

	// Payload: peer count
	binary.LittleEndian.PutUint16(pkt[headerLen:], peerCount)

	r.signInPlace(pkt)
	return pkt
}

func (r *relay) rateAllow(p *peer, now time.Time) bool {
	if r.cfg.rateLimitPPS <= 0 {
		return true
	}
	if p.lastRefill.IsZero() {
		p.lastRefill = now
		p.tokens = r.cfg.rateLimitBurst
	}
	elapsed := now.Sub(p.lastRefill).Seconds()
	if elapsed > 0 {
		p.tokens += elapsed * r.cfg.rateLimitPPS
		if p.tokens > r.cfg.rateLimitBurst {
			p.tokens = r.cfg.rateLimitBurst
		}
		p.lastRefill = now
	}
	if p.tokens >= 1.0 {
		p.tokens -= 1.0
		return true
	}
	return false
}

func (r *relay) upsertPeer(id deviceID, addr *net.UDPAddr, now time.Time) (p *peer, isNew bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	p = r.peers[id]
	if p == nil {
		p = &peer{stateDirty: true}
		r.peers[id] = p
		atomic.AddUint64(&r.m.peersAdded, 1)
		atomic.AddInt64(&r.m.peersCurrent, 1)
		// Mark all existing peers as dirty since peer count changed.
		for _, other := range r.peers {
			other.stateDirty = true
		}
		isNew = true
	}
	p.addr = addr
	p.lastSeen = now
	return p, isNew
}

func (r *relay) expirePeers(now time.Time) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	n := 0
	for id, p := range r.peers {
		if now.Sub(p.lastSeen) > r.cfg.peerTimeout {
			delete(r.peers, id)
			n++
		}
	}
	// If any peers expired, mark remaining peers as dirty.
	if n > 0 {
		for _, p := range r.peers {
			p.stateDirty = true
		}
	}
	return n
}

func (r *relay) cleanupLoop(stop <-chan struct{}) {
	t := time.NewTicker(r.cfg.cleanupEvery)
	defer t.Stop()

	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			expired := r.expirePeers(now)
			if expired > 0 {
				atomic.AddUint64(&r.m.peersExpired, uint64(expired))
				atomic.AddInt64(&r.m.peersCurrent, int64(-expired))
			}
		}
	}
}

func (r *relay) metricsHandler(w http.ResponseWriter, _ *http.Request) {
	out := map[string]any{
		"uptime_seconds":   time.Since(r.m.started).Seconds(),
		"peers_current":    atomic.LoadInt64(&r.m.peersCurrent),
		"peers_added":      atomic.LoadUint64(&r.m.peersAdded),
		"peers_expired":    atomic.LoadUint64(&r.m.peersExpired),
		"recv_total":       atomic.LoadUint64(&r.m.recvTotal),
		"fwd_total":        atomic.LoadUint64(&r.m.fwdTotal),
		"drop_bad_len":     atomic.LoadUint64(&r.m.dropBadLen),
		"drop_bad_magic":   atomic.LoadUint64(&r.m.dropBadMagic),
		"drop_bad_version": atomic.LoadUint64(&r.m.dropBadVersion),
		"drop_bad_type":    atomic.LoadUint64(&r.m.dropBadType),
		"drop_bad_audio":   atomic.LoadUint64(&r.m.dropBadAudio),
		"drop_bad_mac":     atomic.LoadUint64(&r.m.dropBadMAC),
		"drop_ratelimit":   atomic.LoadUint64(&r.m.dropRateLimit),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (r *relay) serveMetrics() {
	if r.cfg.metricsAddr == "" {
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", r.metricsHandler)
	s := &http.Server{
		Addr:              r.cfg.metricsAddr,
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
	}
	log.Printf("metrics on http://%s/metrics\n", r.cfg.metricsAddr)
	if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("metrics server error: %v\n", err)
	}
}

func main() {
	var (
		listen      = flag.String("listen", ":4242", "UDP listen address")
		keyStr      = flag.String("key", "", "HMAC key: hex:<hex> or b64:<base64> (recommended)")
		timeout     = flag.Duration("peer-timeout", 5*time.Second, "peer expiry timeout")
		cleanup     = flag.Duration("cleanup-every", 1*time.Second, "peer cleanup interval")
		pps         = flag.Float64("limit-pps", 0, "per-device packet rate limit (0 disables)")
		burst       = flag.Float64("limit-burst", 0, "per-device burst (defaults to 2*pps if pps>0)")
		metricsAddr = flag.String("metrics", "127.0.0.1:9090", "metrics listen addr (empty disables)")
	)
	flag.Parse()

	if *keyStr == "" {
		fmt.Fprintln(os.Stderr, "error: -key is required (use e.g. -key hex:<...> or -key b64:<...>)")
		os.Exit(2)
	}
	key, err := parseKey(*keyStr)
	if err != nil {
		log.Fatal(err)
	}
	if len(key) < 32 {
		log.Printf("warning: key is %d bytes; spec suggests 32 bytes\n", len(key))
	}
	if *pps > 0 && *burst == 0 {
		*burst = *pps * 2
	}

	cfg := config{
		listenAddr:     *listen,
		key:            key,
		peerTimeout:    *timeout,
		cleanupEvery:   *cleanup,
		rateLimitPPS:   *pps,
		rateLimitBurst: *burst,
		metricsAddr:    *metricsAddr,
	}
	r := newRelay(cfg)

	stop := make(chan struct{})
	defer close(stop)
	go r.cleanupLoop(stop)
	go r.serveMetrics()

	pc, err := net.ListenPacket("udp4", cfg.listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer pc.Close()

	log.Printf("UDP relay listening on %s (v=%d, header=%d, auth=%d@%d)\n", cfg.listenAddr, version, headerLen, authLen, authOffset)

	for {
		n, from, err := pc.ReadFrom(r.readBuf)
		if err != nil {
			continue
		}
		atomic.AddUint64(&r.m.recvTotal, 1)

		if n < headerLen {
			atomic.AddUint64(&r.m.dropBadLen, 1)
			continue
		}

		pkt := r.readBuf[:n]

		if pkt[0] != magic0 || pkt[1] != magic1 {
			atomic.AddUint64(&r.m.dropBadMagic, 1)
			continue
		}
		if pkt[2] != version {
			atomic.AddUint64(&r.m.dropBadVersion, 1)
			continue
		}
		ptype := pkt[3]
		if ptype != typeHello && ptype != typeAudio && ptype != typeBye {
			atomic.AddUint64(&r.m.dropBadType, 1)
			continue
		}

		if !r.verifyMAC(pkt) {
			atomic.AddUint64(&r.m.dropBadMAC, 1)
			continue
		}

		if ptype == typeAudio {
			if n < headerLen+audioHdrLen {
				atomic.AddUint64(&r.m.dropBadAudio, 1)
				continue
			}
			audioLen := int(binary.LittleEndian.Uint16(pkt[headerLen : headerLen+2]))
			if audioLen < 0 || audioLen > maxAudioData {
				atomic.AddUint64(&r.m.dropBadAudio, 1)
				continue
			}
			if n != headerLen+audioHdrLen+audioLen {
				atomic.AddUint64(&r.m.dropBadAudio, 1)
				continue
			}
		}

		now := time.Now()
		addr, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}

		id := parseDeviceID(pkt)
		p, _ := r.upsertPeer(id, addr, now)

		r.mu.Lock()
		allowed := r.rateAllow(p, now)
		r.mu.Unlock()
		if !allowed {
			atomic.AddUint64(&r.m.dropRateLimit, 1)
			continue
		}

		// On HELLO, send STATUS if peer's state is dirty.
		if ptype == typeHello {
			r.mu.Lock()
			if p.stateDirty {
				peerCount := uint16(len(r.peers))
				statusPkt := r.buildStatusPacket(peerCount)
				_, _ = pc.WriteTo(statusPkt, addr)
				p.stateDirty = false
				log.Printf("sent STATUS to %s (peers=%d)", addr, peerCount)
			}
			r.mu.Unlock()
			continue
		}

		if ptype != typeAudio && ptype != typeBye {
			continue
		}

		if cap(r.forwardBuf) < n {
			r.forwardBuf = make([]byte, n)
		}
		out := r.forwardBuf[:n]
		copy(out, pkt)

		// Mark VIA_RELAY and re-sign because flags changed.
		out[18] |= flagViaRelay
		r.signInPlace(out)

		r.mu.RLock()
		for otherID, other := range r.peers {
			if otherID == id {
				continue
			}
			if now.Sub(other.lastSeen) > cfg.peerTimeout {
				continue
			}
			if other.addr == nil {
				continue
			}
			_, _ = pc.WriteTo(out, other.addr)
			atomic.AddUint64(&r.m.fwdTotal, 1)
		}
		r.mu.RUnlock()
	}
}
