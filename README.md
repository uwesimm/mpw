# MPW (Master Password)

A Rust implementation of the Master Password algorithm - a deterministic password generation system where you only need to remember one master password.

## Features

- **CLI tool**: Generate passwords from the command line
- **Web server**: Optional HTTP API for programmatic access
- **Template support**: Multiple password templates (short, long, passphrase, etc.)
- **TLS support**: Optional HTTPS for the web server (build with the `tls` feature)
- **Environment variable support**: Provide master password via `MPW_MASTER_PASSWORD`

## Installation

```bash
cargo install --path mpw
```

Or from source:

```bash
git clone https://github.com/uwesimm/mpw
cd mpw
cargo install --path mpw
```

## Usage

### CLI

Basic usage:

```bash
mpw -t x -k a -c 1
```

This will prompt for:
- User (e.g., your email)
- Master password
- Site name (e.g., github.com)

### Command-line options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--template` | `-t` | Template class: `x` (extra), `l` (long), `m` (medium), `s` (short), `n` (name), `b` (basic), `P` (passphrase), `p` (pin) | `x` |
| `--count` | `-c` | Password counter; increment to rotate a site's password (minimum 1) | `1` |
| `--kind` | `-k` | Usage type: `a` (Authentication), `i` (Login), `r` (Recovery) | `a` |
| `--context` | `-x` | Optional context string (used for recovery answers) | `""` |
| `--user` | `-u` | Username | prompt |
| `--site` | `-s` | Site name | prompt |
| `--serve` | | Start HTTP server | false |
| `--bind` | | HTTP server bind address | `127.0.0.1` |
| `--port` | | HTTP server port | `8080` |
| `--tls-cert` | | TLS certificate file (PEM) | - |
| `--tls-key` | | TLS private key file (PEM) | - |

The master password can only be supplied via `MPW_MASTER_PASSWORD` or an
interactive prompt - never via a command-line flag, because command-line
arguments are visible to other processes (`ps`, `/proc`).

### Examples

Generate a short PIN for a specific site:

```bash
mpw -k a -t p -u user@example.com -s github.com
```

Generate a passphrase using the environment variable:

```bash
export MPW_MASTER_PASSWORD="mypass"
mpw -t P -u alice -s mysite
```

### Web Server

Start the HTTP server:

```bash
mpw --serve --port 8080
```

The server binds to `127.0.0.1` by default and refuses to start in plaintext
mode on a non-loopback address. To serve from other hosts, build with TLS and
provide a certificate and key:

```bash
cargo build --release -p mpw --features tls
mpw --serve --port 8443 --tls-cert cert.pem --tls-key key.pem
```

#### API

**POST /api/generate**

Generate a password via JSON:

```json
{
  "master_password": "your_master_password",
  "user": "user@example.com",
  "site_name": "github.com",
  "counter": 1,
  "context": "",
  "usage": "a",
  "template": "x"
}
```

**Response:**

```json
{
  "password": "FLCUCf7B7TqqT*7Qdk8&"
}
```

**Errors:** `400 Bad Request` with a plain-text reason when required fields are
missing or empty, the counter is below 1, or the usage/template characters are
invalid. `500` is returned only for internal derivation failures; details go to
the server log, not the response.

Key derivation is expensive by design (~0.5-1 s of CPU, ~32 MiB), so the
server serializes at most 4 concurrent derivations; additional requests queue.

## Password Templates

Example outputs for user `alice`, site `example.com`, counter 1:

| Template | Length | Example |
|----------|--------|---------|
| `x` | 20 | `n3[vEGVJs8z1gGXBi2QD` |
| `l` | 14 | `XofeCesg9*Masa` |
| `m` | 8 | `Xof1&Dog` |
| `s` | 4 | `Xof1` |
| `n` | 9 | `xofdedogu` |
| `b` | 8 | `nY01Eft8` |
| `P` | 20 | `xof cesguxeza vare` |
| `p` | 4 | `9301` |

## Usage Types

| Type | Description |
|------|-------------|
| `a` | Authentication (default) |
| `i` | Login |
| `r` | Recovery question |

## Building with TLS

```bash
cargo build --release -p mpw --features tls
```

---

## Architecture Overview

- **CLI mode**: Parses command-line arguments with `clap`, prompts for missing values, calls `masterpassword_rs::generate_password`, and prints the result.
- **HTTP server mode**: Uses **Actix-Web** to expose two routes:
  - `GET /` – serves a static HTML page with a simple password-generation form.
  - `POST /api/generate` – accepts a JSON payload, validates it, and returns a generated password. Derivation runs on a blocking thread, capped by a semaphore.
- TLS can be enabled via `--tls-cert` and `--tls-key` flags; this requires building with the `tls` Cargo feature.
- The core password-generation logic lives in the separate crate `masterpassword_rs` and is reused by both CLI and server paths.

## Security Considerations

- **Local-only default** - the server binds to `127.0.0.1` and refuses to
  serve plaintext HTTP on routable interfaces. It does not require
  authentication, so keep it on loopback or behind TLS plus an authenticating
  reverse proxy.
- **Master password handling** - read from `MPW_MASTER_PASSWORD` or a hidden
  prompt; never accepted via argv, never written to disk or logged.
- **Transport security** - with TLS, the master password and generated
  passwords travel over an encrypted channel. Without TLS they travel as
  plaintext JSON - that is only acceptable on loopback.
- **Denial of service** - key derivation is intentionally expensive; the
  server runs at most 4 derivations concurrently and queues the rest.
- **Same-origin only** - the API sends no CORS headers; browsers from other
  origins cannot read responses.

## Code Quality

- Uses idiomatic Rust error handling with `anyhow`.
- Separation of concerns: CLI parsing, server setup, and password generation are in distinct modules.
- CI enforces `cargo fmt --check`, `cargo clippy -D warnings` (including the `tls` feature), and the full test suite.
- Logging is performed via the `log` crate with configurable level (`Info` by default).

---

## Master Password Algorithm

This implementation follows the [Master Password algorithm](https://en.wikipedia.org/wiki/Master_Password_(algorithm)) developed by Maarten Billemont. The algorithm generates the same password every time for the same combination of:
- Master password
- User identifier
- Site name
- Counter value
- Context string

This means you can regenerate the same password for a site anytime without storing it.

The implementation is interoperable with official clients: length and counter
prefixes are raw big-endian bytes, verified against reference test vectors
(including the official self-test vector). Note that this implementation does
not yet apply the spec's IDNA/NFC input normalization, so enter names and site
names exactly as the other clients would normalize them.

## License

MIT
