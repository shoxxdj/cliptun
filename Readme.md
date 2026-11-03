# cliptun

**cliptun** is a TCP tunnel that transports network connections through a shared clipboard.

It consists of two components:
- **Front**: exposes a local proxy (SOCKS5, SOCKS4/4a, HTTP proxy with `CONNECT`, or plain HTTP requests).
- **Back**: retrieves frames and establishes TCP connections to the requested destinations.

Communication frames are compressed (streaming zstd), can be encrypted and authenticated
(XChaCha20-Poly1305, `--encrypt`), and are protected with CRC32 integrity checks.

## Build

```bash
cargo build --release
```

Requirements: a recent Rust toolchain and a C compiler (the `zstd` crate builds the zstd C library).

To build without the system clipboard backend (file transport only, no `arboard` dependency):

```bash
cargo build --release --no-default-features
```

### Cross-compiling for Windows

Pick one of the following approaches from a Linux or macOS host. All of them produce a standalone
`cliptun.exe`. Because of the zstd C dependency, a **C cross-compiler for the target is required**.

#### Option A: GNU target with mingw-w64 (simplest)

```bash
# 1. Rust target
rustup target add x86_64-pc-windows-gnu

# 2. Cross C compiler / linker
#    Debian/Ubuntu:  sudo apt install mingw-w64
#    Fedora:         sudo dnf install mingw64-gcc
#    macOS (brew):   brew install mingw-w64

# 3. Build
cargo build --release --target x86_64-pc-windows-gnu
```

Output: `target/x86_64-pc-windows-gnu/release/cliptun.exe`

The default linker name for this target is `x86_64-w64-mingw32-gcc`. If yours is installed under another
name, set it in `.cargo/config.toml`:

```toml
[target.x86_64-pc-windows-gnu]
linker = "x86_64-w64-mingw32-gcc"
```

If the resulting executable asks for MinGW runtime DLLs on the Windows machine, link them statically:

```bash
RUSTFLAGS="-C target-feature=+crt-static -C link-arg=-static" \
  cargo build --release --target x86_64-pc-windows-gnu
```

#### Option B: MSVC target with `cargo-xwin`

```bash
cargo install cargo-xwin
rustup target add x86_64-pc-windows-msvc
cargo xwin build --release --target x86_64-pc-windows-msvc
```

Output: `target/x86_64-pc-windows-msvc/release/cliptun.exe`

`cargo-xwin` downloads the Windows SDK/CRT on first use (you accept Microsoft's license) and needs `clang`
and `lld` available on the host.

#### Option C: `cross` (Docker-based)

```bash
cargo install cross
cross build --release --target x86_64-pc-windows-gnu
```

#### Other Windows targets

Replace the target triple, for example `i686-pc-windows-gnu` (32-bit) or `aarch64-pc-windows-msvc` (ARM64,
with `cargo-xwin`). On a headless build you can add `--no-default-features` to leave out the clipboard
backend.

#### Running on Windows

```powershell
.\cliptun.exe front --listen 127.0.0.1:1080
.\cliptun.exe keygen --out cliptun.key
$env:CLIPTUN_KEY = (Get-Content cliptun.key)    # or use --key-file
```

- The system clipboard backend needs an interactive desktop session (it does not work from a Windows service).
- File permission checks on key files (`0600`) are Unix-only. On Windows, restrict access to the key file with
  NTFS permissions yourself.

## Usage

### Back

Run on the machine with network access (for example the isolated virtual machine):

```bash
./cliptun back
```

By default Back only accepts loopback destinations (`localhost`, `127.0.0.1`, `::1`). Allow additional hosts with
`--allow` (repeatable):

```bash
./cliptun back --allow intranet.example --allow 10.0.0.5
```

You can also force **all** connections to a specific destination, ignoring what the client asked for:

```bash
./cliptun back --connect-to 127.0.0.1:8080
```

### Front

Run on the client machine:

```bash
./cliptun front --listen 127.0.0.1:1080
```

The listener detects the protocol automatically from the first byte of each connection, so a single port serves
all of the following:

| Protocol | Notes |
|---|---|
| SOCKS5 | `CONNECT`, no authentication; domain names are resolved by Back (use `socks5h`/"remote DNS") |
| SOCKS4 / SOCKS4a | `CONNECT` only |
| HTTP proxy, `CONNECT` | Tunnels HTTPS and any TCP stream |
| HTTP proxy, absolute URI | `GET http://host/path`; the request is rewritten and sent with `Connection: close` (one stream per request) |
| Direct HTTP request | `GET /path` with a `Host:` header, so you can browse `http://127.0.0.1:1080/` without configuring a proxy (combine with `back --connect-to`) |

Configure your applications to use `127.0.0.1:1080` as a SOCKS5 or HTTP proxy. Examples:

```bash
curl --socks5-hostname 127.0.0.1:1080 http://example.test/
curl -x http://127.0.0.1:1080 http://example.test/
chromium --proxy-server="socks5://127.0.0.1:1080"
```

Front has no authentication: keep it bound to `127.0.0.1`.

## Encryption

Enable authenticated encryption of every frame with `--encrypt` on **both** sides.

### Quick start

```bash
# 1. Generate a key once (file is created with mode 0600 and never overwritten)
./cliptun keygen --out cliptun.key

# 2. Copy cliptun.key to the other machine through a trusted channel

# 3. Start both sides with the same key
./cliptun back  --encrypt --key-file cliptun.key --connect-to 127.0.0.1:8080
./cliptun front --encrypt --key-file cliptun.key
```

The key can also be provided through the `CLIPTUN_KEY` environment variable (64 hexadecimal characters) instead of
`--key-file`:

```bash
export CLIPTUN_KEY=$(cat cliptun.key)
./cliptun front --encrypt
```

The key is intentionally **not** accepted as a command-line argument, because arguments are visible to other users
(`ps`) and end up in shell history.

Both sides must agree: if only one side uses `--encrypt`, or the keys differ, frames are silently ignored and the
front gives up after `--peer-timeout-ms`. Use `--verbose` to see authentication failures.

### Details

| Aspect | Choice |
|---|---|
| Cipher | XChaCha20-Poly1305 (AEAD) |
| Key | 256 bits, shared, generated by the OS CSPRNG (`cliptun keygen`) |
| Nonce | 192 bits, random per frame, sent with the frame (no counter to synchronize) |
| Authenticated header | direction, both session IDs and the sequence number are bound to the ciphertext as associated data |
| Frame marker | `CT4` (encrypted) instead of `CT3` (plain) |
| Downgrade protection | in encrypted mode, plain `CT3` frames are refused |
| Overhead | 40 bytes per non-empty frame (24-byte nonce + 16-byte tag) |

What this gives you:

- **Confidentiality**: tunnelled data cannot be read by other processes that can read the clipboard.
- **Integrity and authenticity**: any modified or forged frame fails authentication and is dropped. Changing the
  header (for example the sequence number) invalidates the frame as well.
- **Replay resistance**: sequence numbers must increase within a session, and a *new* session is only accepted if its
  sequence number is higher than every one Back has already accepted. Sequence numbers start from the Front's clock,
  so replaying frames captured during an earlier session is rejected.

Order of operations is **compress, then encrypt**. Consequences worth knowing:

- Frame sizes remain visible on the channel. If a plain-HTTP stream mixes secrets with attacker-influenced content,
  an observer could learn about the content from compressed sizes (CRIME/BREACH-style). Add `--no-compress` for such
  traffic. HTTPS tunnelled through `CONNECT` is already encrypted and incompressible, so it is not affected.
- Metadata is **not** hidden: timing, frame sizes, direction and the (random) session identifiers are observable.

Limitations:

- The key is a static shared secret: there is no forward secrecy. Anyone who obtains the key file can decrypt
  traffic they captured earlier.
- Anyone able to write to the clipboard can still disrupt the tunnel (drop or overwrite frames); encryption protects
  data, not availability.
- Replay protection relies on Back remembering the highest sequence number it has accepted, which is lost when Back
  restarts. A first frame captured before the restart could then be replayed once. A challenge/response handshake
  would close this gap.
- If the Front's clock moves backwards between two runs, its new session is ignored and Back prints a message
  explaining why.

## Transport

By default, cliptun uses the system clipboard.

To use a shared file instead (for testing or environments without clipboard support):

```bash
./cliptun back --backend file --file /tmp/cliptun
./cliptun front --backend file --file /tmp/cliptun
```

If `--file` is omitted, `cliptun.clip` in the system temporary directory is used.

## Options

All options below are global: they can be given before or after the subcommand.

| Option | Default | Description |
|---|---|---|
| `--backend <clipboard\|file>` | `clipboard` | Transport |
| `--file <path>` | temp dir | File used by `--backend file` |
| `--encrypt` | off | Encrypt and authenticate every frame (see [Encryption](#encryption)) |
| `--key-file <path>` | – | File containing the 64-hex-character key (or use `CLIPTUN_KEY`) |
| `--no-compress` | off | Do not compress outgoing frames (incoming frames are always handled) |
| `--level <1-19>` | `9` | zstd compression level |
| `--chunk <bytes>` | `49152` | Target frame size on the wire; the raw size before compression adapts to the observed ratio (up to ×4) |
| `--poll-ms <ms>` | `50` | Clipboard polling period |
| `--interval-ms <ms>` | `300` | Front polling period when streams are open but idle |
| `--idle-max-ms <ms>` | `1500` | Idle polling gradually slows down to this period |
| `--resend-ms <ms>` | `3000` | Delay before resending an unanswered frame (doubled on each retry, up to ×4) |
| `--peer-timeout-ms <ms>` | `30000` | Silence from the peer after which Front closes its streams |
| `-v`, `--verbose` | off | Detailed logging |

Subcommand options:

| Command | Option | Description |
|---|---|---|
| `front` | `--listen <addr>` | Listen address (default `127.0.0.1:1080`) |
| `back` | `--connect-to <host:port>` | Force every connection to this destination |
| `back` | `--allow <host>` | Allow an extra destination host (repeatable; loopback is always allowed) |
| `keygen` | `--out <path>` | Write the key to a new file (mode 0600) instead of printing it |

## How It Works

### Communication Architecture

Front and Back communicate through a shared clipboard, which acts as a transport channel between the two processes.

No direct network connection between Front and Back is required.

- **Front** receives proxy connections from client applications.
- **Back** establishes the actual TCP connections to the requested destinations.
- The shared clipboard transports requests and responses between both components.

### Frame Protocol

Each communication frame follows this format:

```text
CT3|<direction>|<gen>|<peer>|<sequence>|<base64(wire)>|<crc32>      plain
CT4|<direction>|<gen>|<peer>|<sequence>|<base64(wire)>|<crc32>      encrypted (--encrypt)
```

| Field | Description |
|---|---|
| `CT3` / `CT4` | Protocol identifier (plain / encrypted) |
| `direction` | `F` (Front) or `B` (Back) |
| `gen` | Random session identifier of the sender (hex) |
| `peer` | Session identifier of the other side as known by the sender (`0` if unknown) |
| `sequence` | Frame sequence number |
| `wire` | Base64-encoded frame content (see below); for `CT4`: `nonce(24) ‖ ciphertext ‖ tag(16)` |
| `crc32` | Checksum of the transmitted bytes, used to detect truncated or corrupted frames |

The `wire` content starts with a flag byte:

| Flag | Meaning |
|---|---|
| `0` | Raw binary messages |
| `1` | Messages compressed in the streaming zstd context |
| `2` | `RESET`: the sender asks the other side to restart the session |

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

Front is always responsible for initiating exchanges. Back only responds to incoming frames. While no stream is
open, Front does not touch the clipboard at all.

### Compression

Each direction has its own persistent zstd stream, flushed at the end of every frame. Earlier frames therefore
serve as history for later ones (repeated headers, HTML, JavaScript...), and the stream is primed with a built-in
dictionary of typical HTTP traffic. The raw size of a frame adapts to the compression ratio observed so far, so
fewer clipboard round trips are needed for compressible data. Frames smaller than 48 bytes are sent raw, and
decompression is capped at 16 MiB per frame.

Because both sides advance their compression state exactly once per frame, the protocol relies on frames being
delivered exactly once and in order, which the stop-and-wait cycle guarantees.

### Sessions and Recovery

Each process picks a random session identifier (`gen`) at start-up, and every frame carries both its own and the
one it believes the other side has:

- A new Front session makes Back close all of its streams and start from a fresh state.
- If Back restarts, Front notices the changed identifier (or receives a `RESET`), closes its streams and starts a
  new session. Frames replayed from before a restart are rejected.
- If the peer stays silent longer than `--peer-timeout-ms`, Front closes its streams instead of hanging.
- If a frame cannot be decoded, the receiver requests a reset so that the compression states cannot stay out of sync.

### Reliability

The protocol includes several mechanisms to handle clipboard synchronization issues:

- **Sequence numbers** prevent outdated frames from being processed.
- **CRC32** detects corrupted or truncated frames (and AEAD tags do the same for encrypted frames).
- **Retransmission** allows Front to resend requests when no response is received within `--resend-ms`, with
  exponential backoff.
- **Response caching** allows Back to rewrite its previous response when it sees the same request again, which also
  recovers from a lost response.
- **Flow control**: each stream has a 256 KiB window on Back, released when its data leaves in a frame, so a fast
  server cannot fill memory faster than the clipboard can drain it.
- **Adaptive polling**: idle polling slows down progressively and wakes up immediately when there is data to send.
- **Compression** reduces the amount of data transported through the clipboard.

### TCP Connection Handling

When Front receives a connection request (SOCKS or HTTP), it sends an `Open` message containing the requested
hostname and port.

Back establishes the TCP connection from its own network environment, subject to its destination policy
(`--connect-to`, `--allow`, loopback by default).

Once connected, TCP data is exchanged through `Data` messages in both directions until the connection is closed.

### Known Limitations

- Half-closed TCP connections are not supported: closing one direction closes the stream.
- Only `CONNECT`-style TCP streams are supported (no UDP, no SOCKS `BIND`).
- Throughput is bounded by how fast the clipboard synchronizes between the two machines.
- Downloads towards a slow client accumulate on the Front side (the flow-control window is released when data leaves
  Back, not when the client has consumed it).

In short, **Front acts as the proxy entry point, Back acts as the TCP connector, and the shared clipboard transports
all requests and responses between them, compressed and, with `--encrypt`, authenticated and encrypted.**
