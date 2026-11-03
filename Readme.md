# cliptun

**cliptun** is a TCP tunnel that transports network connections through a shared clipboard.

It consists of two components:
- **Front**: exposes a local SOCKS5 proxy.
- **Back**: retrieves frames and establishes TCP connections to the requested destinations.

Communication frames are compressed and protected with CRC32 integrity checks.

## Build

```bash
cargo build --release
```

## Usage

### Back

Run on the machine with network access:

```bash
./cliptun back
```

Connections are established to the destinations received from Front.

You can also force all connections to a specific destination:

```bash
./cliptun back --connect-to 127.0.0.1:8080
```

### Front

Run on the client machine:

```bash
./cliptun front --listen 127.0.0.1:1080
```

Configure your applications to use the SOCKS5 proxy:

```text
127.0.0.1:1080
```

## Transport

By default, cliptun uses the system clipboard.

To use a shared file instead (for testing or environments without clipboard support):

```bash
./cliptun back --backend file --file /tmp/cliptun
./cliptun front --backend file --file /tmp/cliptun
```

## Options

Use `--verbose` to enable detailed logging.

Transport, compression, and synchronization parameters can also be configured through global command-line options.

## How It Works

### Communication Architecture

Front and Back communicate through a shared clipboard, which acts as a transport channel between the two processes.

No direct network connection between Front and Back is required.

- **Front** receives SOCKS5 connections from client applications.
- **Back** establishes the actual TCP connections to the requested destinations.
- The shared clipboard transports requests and responses between both components.

### Frame Protocol

Each communication frame follows this format:

```text
CT2|<direction>|<sequence>|<base64(payload)>|<crc32>
```

| Field | Description |
|---|---|
| `CT2` | Protocol identifier |
| `direction` | `F` (Front) or `B` (Back) |
| `sequence` | Frame sequence number |
| `payload` | Base64-encoded binary messages |
| `crc32` | Integrity checksum |

Payloads can optionally be compressed using Deflate.

### Message Types

Each frame contains one or more binary messages:

| Message | Description |
|---|---|
| `Open` | Request to establish a TCP connection |
| `Opened` | Connection result (success or failure) |
| `Data` | TCP data sent or received |
| `Close` | Close a TCP stream |

Each TCP connection is identified by a unique stream ID, allowing multiple connections to share the same transport.

### Request/Response Cycle

Communication follows a half-duplex master/slave model:

1. Front collects pending messages.
2. Front writes a frame `F` with sequence number N.
3. Back reads and processes the frame.
4. Back writes a response frame `B` with the same sequence number N.
5. Front reads the response and dispatches received messages.
6. Front increments the sequence number and starts the next cycle.

Front is always responsible for initiating exchanges. Back only responds to incoming frames.

### Reliability

The protocol includes several mechanisms to handle clipboard synchronization issues:

- **Sequence numbers** prevent outdated frames from being processed.
- **CRC32** detects corrupted frames.
- **Retransmission** allows Front to resend requests when no response is received within `--resend-ms`.
- **Response caching** allows Back to rewrite its previous response when it receives a duplicate request.
- **Compression** reduces the amount of data transported through the clipboard.

### TCP Connection Handling

When Front receives a SOCKS5 connection request, it sends an `Open` message containing the requested hostname and port.

Back establishes the TCP connection from its own network environment.

Once connected, TCP data is exchanged through `Data` messages in both directions until the connection is closed.

In short, **Front acts as the SOCKS5 entry point, Back acts as the TCP connector, and the shared clipboard transports all requests and responses between them.**
