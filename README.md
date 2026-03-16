# MPW (Master Password)

A Rust implementation of the Master Password algorithm - a deterministic password generation system where you only need to remember one master password.

## Features

- **CLI tool**: Generate passwords from the command line
- **Web server**: Optional HTTP API for programmatic access
- **Template support**: Multiple password templates (short, long, passphrase, etc.)
- **TLS support**: Optional HTTPS for the web server
- **Environment variable support**: Provide master password via `MPW_MASTER_PASSWORD`

## Installation

```bash
cargo install --path mpw
```

Or from source:

```bash
git clone https://github.com/your-repo/mpw
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
| `--count` | `-c` | Number of passwords to generate | `1` |
| `--kind` | `-k` | Usage type: `a` (Authentication), `l` (Login), `r` (Recovery) | `a` |
| `--context` | `-x` | Optional context string | `""` |
| `--user` | `-u` | Username | prompt |
| `--password` | `-p` | Master password | prompt/env |
| `--site` | `-s` | Site name | prompt |
| `--serve` | | Start HTTP server | false |
| `--bind` | | HTTP server bind address | `127.0.0.1` |
| `--port` | | HTTP server port | `8080` |
| `--tls-cert` | | TLS certificate file (PEM) | - |
| `--tls-key` | | TLS private key file (PEM) | - |

### Examples

Generate a short PIN for a specific site:

```bash
mpw -k a -s a -t p -u user@example.com -s github.com -p mymasterpassword
```

Generate a passphrase using environment variable:

```bash
export MPW_MASTER_PASSWORD="mypass"
mpw -t P -u alice -p mysite
```

### Web Server

Start the HTTP server:

```bash
mpw --serve --port 8080
```

With TLS (requires building with `--features tls`):

```bash
mpw --serve --port 8080 --tls-cert cert.pem --tls-key key.pem
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

## Password Templates

| Template | Description | Example |
|----------|-------------|---------|
| `x` | Extra complex (default) | `FLCUCf7B7TqqT*7Qdk8&` |
| `l` | Long | `AlpineRiverMountain` |
| `m` | Medium | `Cobalt5` |
| `s` | Short | `M4p` |
| `n` | Name-like | `alexander` |
| `b` | Basic | `adobe1986` |
| `P` | Passphrase | `correct-horse-battery` |
| `p` | Pin | `4829` |

## Usage Types

| Type | Description |
|------|-------------|
| `a` | Authentication (default) |
| `l` | Login |
| `r` | Recovery question |

## Building with TLS

TLS support requires building with the `tls` feature:

```bash
cargo build --release --features tls
```

## Master Password Algorithm

This implementation follows the [Master Password algorithm](hhttps://en.wikipedia.org/wiki/Master_Password_(algorithm)) developed by  Maarten Billemont. The algorithm generates the same password every time for the same combination of:
- Master password
- User identifier
- Site name
- Counter value
- Context string

This means you can regenerate the same password for a site anytime without storing it.

## License

MIT
