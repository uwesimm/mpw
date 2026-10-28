# Masterpassword

A Rust implementation of the Master Password algorithm (see https://en.wikipedia.org/wiki/Master_Password_(algorithm)).

## Usage

```
Usage: mpw [OPTIONS]

Options:
  -t, --template <TEMPLATE>    template to use: x-extra,l-long,m-medium,s-short,n-name,P-passphrase,p-pin,b-basic [default: x]
  -c, --count <COUNT>          password counter (increment to rotate the password for a site; minimum 1) [default: 1]
  -k, --kind <USAGE>           a=Authentication, i=Login, r=Recovery [default: a]
  -x, --context <CONTEXT>      optional context [default: ""]
  -u, --user <USER>            [default: ""]
  -s, --site <SITE>            [default: ""]
      --serve                  start HTTP server
      --bind <BIND>            bind address for HTTP server (plaintext is only allowed on loopback addresses) [default: 127.0.0.1]
      --port <PORT>            port for HTTP server [default: 8080]
      --tls-cert <TLS_CERT>    TLS certificate file (PEM). If provided together with --tls-key, server will use HTTPS [default: ""]
      --tls-key <TLS_KEY>      TLS private key file (PEM). If provided together with --tls-cert, server will use HTTPS [default: ""]
  -h, --help                   Print help
  -V, --version                Print version
```

## Environment Variables

- `MPW_MASTER_PASSWORD`: Set master password for non-interactive use (CI/CD).
  The master password is deliberately *not* a command-line flag: argv is
  visible to other processes via `ps`.

## Error Messages

The application provides detailed error messages when invalid options are provided:

- Invalid template: `template 'z' not recognized. Valid: x=extra, l=long, m=medium, s=short, n=name, b=basic, P=passphrase, p=pin`
- Invalid usage: `usage character 'x' not recognized. Valid options: 'a' (Authentication), 'i' (Login), 'r' (Recovery)`
- Counter below 1: `counter must be at least 1`

## Build

```
cargo build --release -p mpw
cargo install --path .
```

## Server (HTTP / HTTPS)

Start the built-in web server with `--serve`. Server-related CLI options:

- `--bind <ADDR>`: bind address (default: `127.0.0.1`). Plaintext HTTP is refused on non-loopback addresses.
- `--port <PORT>`: port (default: `8080`)
- `--tls-cert <FILE>`: TLS certificate (PEM). When set together with `--tls-key`, the server will use HTTPS.
- `--tls-key <FILE>`: TLS private key (PEM). When set together with `--tls-cert`, the server will use HTTPS.

HTTPS requires building with the `tls` feature:

```
cargo build --release -p mpw --features tls
```

Examples:

HTTP (default, loopback only):
```
cargo run -p mpw -- --serve
```

HTTPS on all interfaces (with PEM cert/key):
```
cargo run -p mpw --features tls -- --serve --bind 0.0.0.0 --port 8443 --tls-cert /path/to/cert.pem --tls-key /path/to/key.pem
```

API example (JSON POST):
```
curl -s -X POST -H "content-type: application/json" \
  -d '{ "master_password": "1", "user": "1", "site_name": "1" }' \
  http://127.0.0.1:8080/api/generate | jq .
```

The API returns `400 Bad Request` (with the reason as plain text) for empty or
missing `master_password`/`user`/`site_name`, a counter below 1, or invalid
usage/template characters. At most 4 key derivations run concurrently; further
requests queue. No CORS headers are sent - the API is same-origin only.

For HTTPS use `https://...` and, for self-signed certificates, add `-k` to `curl`.

## License

MIT
