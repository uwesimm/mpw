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