# tcpsocks

`tcpsocks` is a reverse SOCKS5 proxy:

- **Server** exposes a local SOCKS5 port (for your applications).
- **Client** connects to the server over a control TCP channel and performs the **actual outbound TCP dial** to the requested destination.

In other words, when an app connects to the server's SOCKS5 port and requests `CONNECT host:port`, the server forwards that request to one of the connected clients, and the client dials `host:port` from its network.

## Project layout

- `auth.go` (root package `tcpsocks`) — PSK loading/selection logic
- `client/client.go` — client (agent)
- `server/server.go` — server (SOCKS5 endpoint + control-plane)

## Ports and hardcoded stubs

- **Server control port is hardcoded to `1080`** in `server/server.go` (`CONTROL_PORT = 1080`).
- **Server SOCKS5 listen port is configurable** via `-socks <port>` or a single positional `<port>` argument.

Client side:

- `client/client.go` contains a **hardcoded stub**:
  - `SOCKSIP = "0"` (default) means **use CLI arguments**: `./client <server_ip> <control_port>`
  - If you change `SOCKSIP` to `"IP PORT"` (example: `"10.0.0.5 1080"`), the client will use that value and **no CLI args are required**.

## Security model

The control channel supports optional encryption (AEAD):

- When a **PSK (pre-shared key) is configured**, client and server negotiate **AES-256-GCM** and encrypt all control frames (except a small handshake/heartbeat subset).
- By default, both sides **refuse to run without a PSK**, because plaintext control traffic is insecure.

### Runtime key override

You can override the embedded key at runtime via:

- `SOCKS_PSK_HEX` — **64 hex characters** (32 bytes).

This must match on both client and server.

### Insecure plaintext mode (not recommended)

- `SOCKS_ALLOW_PLAINTEXT=1` — allows starting without a PSK (control channel will be plaintext)
- `SOCKS_NO_AEAD=1` — disables AEAD even if a PSK is present

For safety, `SOCKS_NO_AEAD=1` is rejected unless `SOCKS_ALLOW_PLAINTEXT=1` is also set.

## Building

From the repository root (`tcpsocks/`):

### 1) Build with an explicit PSK embedded at link time

Use the same PSK for both binaries:

```bash
PSK=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

go build -ldflags "-X tcpsocks.BuildPSKHex=$PSK" -o tcpsocks-server ./server

go build -ldflags "-X tcpsocks.BuildPSKHex=$PSK" -o tcpsocks-client ./client
```

### 2) Auto-generate a PSK and embed it

This uses `go generate`:

- If you did not provide a PSK, the generator creates a random 32-byte key,
- **prints it to stdout**,
- and writes it into `internal/keydata/keydata.go`.

One-liner build:

```bash
go generate ./... && go build -o tcpsocks-server ./server && go build -o tcpsocks-client ./client
```

Custom key for generation (two options):

1) Via environment variable consumed by the generator:

```bash
PSK=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
PSK_HEX=$PSK go generate ./...
```

2) Run the generator directly:

```bash
PSK=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
go run ./internal/keygen -out ./internal/keydata/keydata.go -psk "$PSK"
```

> Security note: the key is embedded into the binary. Treat the produced binary as a secret.

## Running

### Server

The server listens on:

- `0.0.0.0:1080` (control, hardcoded)
- `0.0.0.0:<socks_port>` (SOCKS5)

Examples:

```bash
./tcpsocks-server -socks 1081
# or
./tcpsocks-server 1081
```

### Client

Connect to the server control port:

```bash
./tcpsocks-client 1.2.3.4 1080
```

Or install as a system service (requires root):

```bash
./tcpsocks-client service 1.2.3.4 1080
```

Disable service installation logic:

```bash
SOCKS_NO_SERVICE=1 ./tcpsocks-client 1.2.3.4 1080
```

## Using the SOCKS5 proxy

Point your application to the server's SOCKS port (example `1081`). For example (hostname resolution through the proxy):

```bash
curl --socks5-hostname 127.0.0.1:1081 http://example.com
```

## Server console

If server stdin is a TTY, it supports a simple console command:

- `clients` — show connected clients
- `clients use auto` — auto routing (default)
- `clients use <ip>` — pin routing to a specific client IP
- `clients use <id>` — pin routing by numeric client ID
- `clients use status` — show current routing mode

## Limitations

- SOCKS5: supports **CONNECT** and **NO AUTH** only.
- Address types: **IPv4** and **DOMAIN**. (No IPv6 in this implementation.)
- TCP only (no UDP ASSOCIATE).
