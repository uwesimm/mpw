//! MasterPassword‑rs
//!
//! A pure‑Rust implementation of the Master Password algorithm.
//! Provides `generate_password` and an ergonomic `PasswordBuilder`.
//! See the README for usage examples.
// Re-export public API from sub‑modules.
pub mod crypto;
pub mod templates;

pub use crate::crypto::{generate_password, PasswordBuilder};

/// Base URL of the git repository for this crate.
pub const REPO_URL: &str = "https://github.com/uwesimm/mpw";

#[cfg(test)]
mod tests {
    use crate::crypto::{generate_password, PasswordBuilder};

    #[test]
    fn test_u32_as_string_small_values() {
        for &x in &[0u32, 1u32, 3u32, 127u32] {
            let s = crate::crypto::u32_as_string(x);
            assert_eq!(s.as_bytes(), &x.to_be_bytes());
        }
    }

    #[test]
    fn deterministic_small_params() {
        let params = scrypt::Params::new(8, 1, 1, 64).unwrap();
        let pw1 = generate_password("password", "bob", "mysite", 1, "", 'a', 'p', Some(params)).unwrap();
        let pw2 = generate_password(
            "password",
            "bob",
            "mysite",
            1,
            "",
            'a',
            'p',
            Some(scrypt::Params::new(8, 1, 1, 64).unwrap()),
        ).unwrap();
        assert_eq!(pw1, pw2);
        assert_eq!(pw1.len(), 4);
        assert!(pw1.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn full_mpw() {
        let pw1 = generate_password("1", "1", "1", 1, "", 'a', 'x', None).unwrap();
        assert_eq!(pw1, "FLCUCf7B7TqqT*7Qdk8&");
    }

    // --- Additional tests (items 1‑10) ---

    #[test]
    fn invalid_usage_character() {
        let err = generate_password("pw", "u", "s", 0, "", 'z', 'x', None).unwrap_err();
        assert!(err.to_string().contains("usage character 'z' not recognized"));
    }

    #[test]
    fn invalid_template_character() {
        let err = generate_password("pw", "u", "s", 0, "", 'a', 'z', None).unwrap_err();
        assert!(err.to_string().contains("template 'z' not recognized"));
    }

    #[test]
    fn empty_master_password() {
        let pw = generate_password("", "user", "site", 0, "", 'a', 'p', None).unwrap();
        // Should still produce a deterministic 4‑digit password.
        assert_eq!(pw.len(), 4);
        assert!(pw.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn non_ascii_user_and_site() {
        let pw = generate_password("master", "用户", "站点", 0, "", 'a', 'p', None).unwrap();
        assert_eq!(pw.len(), 4);
    }


    #[test]
    fn different_templates_produce_different_passwords() {
        let pw_x = generate_password("master", "user", "site", 0, "", 'a', 'x', None).unwrap();
        let pw_l = generate_password("master", "user", "site", 0, "", 'a', 'l', None).unwrap();
        assert_ne!(pw_x, pw_l);
    }

    #[test]
    fn unicode_context() {
        let pw = generate_password("master", "user", "site", 0, "上下文", 'a', 'x', None).unwrap();
        assert_eq!(pw.len(), 20); // 'x' template yields 20 chars
    }

    #[test]
    fn performance_benchmark() {
        // Use low‑cost scrypt parameters to keep the test fast.
        let low_params = scrypt::Params::new(8, 1, 1, 64).unwrap();
        let start = std::time::Instant::now();
        let _ = generate_password("master", "user", "site", 0, "", 'a', 'x', Some(low_params)).unwrap();
        let elapsed = start.elapsed();
        // Ensure it runs in under 10 ms on typical hardware.
        assert!(elapsed.as_millis() < 20, "Password generation too slow: {} ms", elapsed.as_millis());
    }

    #[test]
    fn template_char_sets_v_and_c() {
        use crate::templates::TEMPLATE_CHARS;
        assert_eq!(TEMPLATE_CHARS.get(&'V'), Some(&"AEIOU"));
        assert_eq!(TEMPLATE_CHARS.get(&'C'), Some(&"BCDFGHJKLMNPQRSTVWXYZ"));
    }

    #[test]
    fn builder_matches_direct_call() {
        let pw_direct = generate_password("master", "user", "site", 0, "", 'a', 'x', None).unwrap();
        let pw_builder = PasswordBuilder::new("master", "user", "site")
            .counter(0)
            .usage('a')
            .template_char('x')
            .build()
            .unwrap();
        assert_eq!(pw_direct, pw_builder);
    }

}
