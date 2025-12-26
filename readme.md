# Masterpassword

This is a rust implementation of the masterpassword algorithm (see https://en.wikipedia.org/wiki/Master_Password_(algorithm) ).

## usage:

```
Usage: mpw [OPTIONS]

Options:
  -t, --template <TEMPLATE>  template to use: x-extra,l-long,m-medium,s-short,n-normal,P-passphrase,b-basic [default: x]
  -c, --count <COUNT>        count [default: 1]
  -k, --kind <USAGE>         a=Authentication, l=Login, r=Recovery [default: a]
  -x, --context <CONTEXT>    optional context [default: ]
  -h, --help                 Print help
uwe@uwes-macbook-air mpw % 
```

## Build

```
cargo build --release
cargo install --path .
```

## Server (HTTP / HTTPS)

Start the built-in web server with `--serve`. Server-related CLI options:

- `--bind <ADDR>`: bind address (default: `127.0.0.1`)
- `--port <PORT>`: port (default: `8080`)
- `--tls-cert <FILE>`: TLS certificate (PEM). When set together with `--tls-key`, the server will use HTTPS.
- `--tls-key <FILE>`: TLS private key (PEM). When set together with `--tls-cert`, the server will use HTTPS.

Examples:

HTTP (default):
```
cargo run -- --serve
```

Bind to all interfaces and port 8080:
```
cargo run -- --serve --bind 0.0.0.0 --port 8080
```

HTTPS (with PEM cert/key):
```
cargo run -- --serve --bind 0.0.0.0 --port 8443 --tls-cert /path/to/cert.pem --tls-key /path/to/key.pem
```

API example (JSON POST):
```
curl -s -X POST -H "content-type: application/json" \
  -d '{ "master_password": "1", "user": "1", "site_name": "1" }' \
  http://127.0.0.1:8080/api/generate | jq .
```

For HTTPS use `https://...` and, for self-signed certificates, add `-k` to `curl`.

OpenSSL / macOS note

The optional HTTPS support uses the `openssl` crate which links to system OpenSSL. On macOS you can install OpenSSL via Homebrew:

```
brew install openssl
export OPENSSL_DIR="$(brew --prefix openssl@3)"
export PKG_CONFIG_PATH="$OPENSSL_DIR/lib/pkgconfig"
```

Then build as usual:

```
cargo build
```