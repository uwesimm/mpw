//! MasterPassword‑rs
//!
//! A pure‑Rust implementation of the Master Password algorithm.
//! Provides `generate_password` and an ergonomic `PasswordBuilder`.
//! See the README for usage examples.
// Re-export public API from sub‑modules.
pub mod crypto;
pub mod templates;

pub use crate::crypto::{generate_password, is_valid_template, is_valid_usage, PasswordBuilder};

/// Base URL of the git repository for this crate.
pub const REPO_URL: &str = "https://github.com/uwesimm/mpw";

#[cfg(test)]
mod tests {
    use crate::crypto::{generate_password, PasswordBuilder};

    #[test]
    fn deterministic_small_params() {
        let params = scrypt::Params::new(8, 1, 1, 64).unwrap();
        let pw1 =
            generate_password("password", "bob", "mysite", 1, "", 'a', 'p', Some(params)).unwrap();
        let pw2 = generate_password(
            "password",
            "bob",
            "mysite",
            1,
            "",
            'a',
            'p',
            Some(scrypt::Params::new(8, 1, 1, 64).unwrap()),
        )
        .unwrap();
        assert_eq!(pw1, pw2);
        assert_eq!(pw1.len(), 4);
        assert!(pw1.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn full_mpw() {
        let pw1 = generate_password("1", "1", "1", 1, "", 'a', 'x', None).unwrap();
        assert_eq!(pw1, "FLCUCf7B7TqqT*7Qdk8&");
    }

    #[test]
    fn official_vector() {
        // Self-test vector from the reference implementations:
        // name "user", password "password", site "example.com",
        // counter 1, authentication namespace, "long" template.
        let pw =
            generate_password("password", "user", "example.com", 1, "", 'a', 'l', None).unwrap();
        assert_eq!(pw, "ZedaFaxcZaso9*");
    }

    // --- Additional tests ---

    #[test]
    fn invalid_usage_character() {
        let err = generate_password("pw", "u", "s", 1, "", 'z', 'x', None).unwrap_err();
        assert!(err
            .to_string()
            .contains("usage character 'z' not recognized"));
    }

    #[test]
    fn invalid_template_character() {
        let err = generate_password("pw", "u", "s", 1, "", 'a', 'z', None).unwrap_err();
        assert!(err.to_string().contains("template 'z' not recognized"));
    }

    #[test]
    fn different_templates_produce_different_passwords() {
        let pw_x = generate_password("master", "user", "site", 1, "", 'a', 'x', None).unwrap();
        let pw_l = generate_password("master", "user", "site", 1, "", 'a', 'l', None).unwrap();
        assert_ne!(pw_x, pw_l);
    }

    #[test]
    fn unicode_context() {
        let pw = generate_password("master", "user", "site", 1, "上下文", 'a', 'x', None).unwrap();
        assert_eq!(pw.len(), 20); // 'x' template yields 20 chars
    }

    #[test]
    fn performance_smoke() {
        // Use low‑cost scrypt parameters to keep the test fast. This is a
        // smoke test, not a benchmark: the bound is deliberately generous so
        // it cannot flake on loaded or debug-built CI runners.
        let low_params = scrypt::Params::new(8, 1, 1, 64).unwrap();
        let start = std::time::Instant::now();
        let pw =
            generate_password("master", "user", "site", 1, "", 'a', 'x', Some(low_params)).unwrap();
        assert_eq!(pw.len(), 20);
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_millis() < 100,
            "Password generation unexpectedly slow: {} ms",
            elapsed.as_millis()
        );
    }

    #[test]
    fn template_char_sets_v_and_c() {
        use crate::templates::TEMPLATE_CHARS;
        assert_eq!(TEMPLATE_CHARS.get(&'V'), Some(&"AEIOU"));
        assert_eq!(TEMPLATE_CHARS.get(&'C'), Some(&"BCDFGHJKLMNPQRSTVWXYZ"));
    }

    #[test]
    fn builder_matches_direct_call() {
        let pw_direct = generate_password("master", "user", "site", 5, "", 'a', 'x', None).unwrap();
        let pw_builder = PasswordBuilder::new("master", "user", "site")
            .counter(5)
            .usage('a')
            .template_char('x')
            .build()
            .unwrap();
        assert_eq!(pw_direct, pw_builder);
    }

    #[test]
    fn builder_defaults() {
        // Default counter is 1, usage 'a', template 'x'.
        let pw_builder = PasswordBuilder::new("master", "user", "site")
            .build()
            .unwrap();
        let pw_direct = generate_password("master", "user", "site", 1, "", 'a', 'x', None).unwrap();
        assert_eq!(pw_builder, pw_direct);
    }

    #[test]
    fn builder_rejects_empty_inputs() {
        let err = PasswordBuilder::new("", "user", "site")
            .build()
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("master password must not be empty"));
    }
}
