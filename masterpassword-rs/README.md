# masterpassword-rs

A pure‑Rust implementation of the **Master Password** algorithm.

## Usage
```rust
use masterpassword_rs::generate_password;

let pw = generate_password(
    "my‑master‑pw",
    "alice",
    "example.com",
    1,
    "",
    'a', // usage: authentication
    'x', // template: extra‑complex (default)
    None, // optional custom scrypt parameters
).expect("password generation failed");

println!("Generated password: {}", pw);
```

You can also use the ergonomic builder:
```rust
use masterpassword_rs::PasswordBuilder;

let pw = PasswordBuilder::new("my‑master‑pw", "alice", "example.com")
    .counter(1)
    .usage('a')
    .template('x')
    .build()
    .expect("password generation failed");
```

## Security notes
- The algorithm is **deterministic**; the same inputs always produce the same password.
- It uses **scrypt** (default N=2¹⁵, r=8, p=2) and **HMAC‑SHA256** internally, both considered strong.
- No random number generator is involved, so the output is reproducible but not suitable for generating *new* secrets without a strong master password.
- Debug logging of secret material has been removed to avoid accidental leakage.

## Testing
Run the test suite with:
```
cargo test
```
The crate includes unit tests covering edge cases, invalid inputs, and boundary parameter values.

## License
MIT
