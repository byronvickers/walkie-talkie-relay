# UDP Relay for ESP32 Walkie-Talkie

Go-based UDP relay server that facilitates audio communication between ESP32 devices. Devices send packets to the relay, which broadcasts audio to all other connected peers.

## Build & Run

```bash
go build -o relay .
./relay -key "hex:<32-byte-hex-key>" -listen ":4242"
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-listen` | `:4242` | UDP listen address |
| `-key` | (required) | HMAC key (`hex:<hex>` or `b64:<base64>`) |
| `-peer-timeout` | `5s` | Peer expiry timeout |
| `-cleanup-every` | `1s` | Peer cleanup interval |
| `-limit-pps` | `0` | Per-device packet rate limit (0 = disabled) |
| `-limit-burst` | `2*pps` | Per-device burst capacity |
| `-metrics` | `127.0.0.1:9090` | Metrics HTTP address (empty = disabled) |

## Protocol

### Packet Structure (36-byte header)

```
Bytes 0-1:   Magic 'K','W' (0x4B, 0x57)
Byte 2:      Version (0x02)
Byte 3:      Type: HELLO=0x01, AUDIO=0x02, BYE=0x03
Bytes 4-9:   Device ID (6 bytes, little-endian)
Bytes 10-13: Sequence number (4 bytes, little-endian)
Bytes 14-19: Flags (6 bytes; bit 1 = VIA_RELAY)
Bytes 20-35: Auth tag (16 bytes HMAC-SHA256)
```

### Audio Payload (AUDIO packets only)

```
Bytes 36-37: Audio length (2 bytes, little-endian, max 800)
Bytes 38+:   Audio data
```

## Validation Pipeline

1. Length check (min 36 bytes)
2. Magic bytes
3. Version
4. Packet type
5. HMAC verification
6. Rate limit
7. Replay detection (sequence must increase for AUDIO)

## Relay Behavior

- Tracks peers by device ID with timeout-based expiry
- On AUDIO: sets VIA_RELAY flag, re-signs packet, broadcasts to other peers
- Metrics available at `GET /metrics`
