use anyhow::Context;
use anyhow::Result;
use hmac::{Hmac, Mac};
use scrypt::{scrypt, Params};
use sha2::Sha256;

use crate::templates::{BASE_KEY, TEMPLATES, TEMPLATE_CHARS};

/// Default scrypt parameters from the Master Password specification
/// (N = 2^15, r = 8, p = 2, 64-byte output).
fn default_scrypt_params() -> Params {
    // The parameters are constants known to be valid.
    Params::new(15, 8, 2, 64).expect("valid default scrypt params")
}

/// Returns `true` if `usage` is a recognized namespace character (`'a'`, `'i'` or `'r'`).
pub fn is_valid_usage(usage: char) -> bool {
    BASE_KEY.contains_key(&usage)
}

/// Returns `true` if `template_char` selects a defined password template.
pub fn is_valid_template(template_char: char) -> bool {
    TEMPLATES.contains_key(&template_char)
}

/// Builder for password generation – provides a more ergonomic API.
#[derive(Debug)]
pub struct PasswordBuilder {
    master_password: String,
    user: String,
    site_name: String,
    counter: u32,
    context: String,
    usage: char,
    template_char: char,
    scrypt_params: Option<Params>,
}

impl Default for PasswordBuilder {
    fn default() -> Self {
        Self {
            master_password: String::new(),
            user: String::new(),
            site_name: String::new(),
            counter: 1,
            context: String::new(),
            usage: 'a',
            template_char: 'x',
            scrypt_params: None,
        }
    }
}

impl PasswordBuilder {
    /// Create a new builder with the three required fields.
    pub fn new(
        master_password: impl Into<String>,
        user: impl Into<String>,
        site_name: impl Into<String>,
    ) -> Self {
        Self {
            master_password: master_password.into(),
            user: user.into(),
            site_name: site_name.into(),
            ..Default::default()
        }
    }

    pub fn counter(mut self, counter: u32) -> Self {
        self.counter = counter;
        self
    }
    pub fn context(mut self, ctx: impl Into<String>) -> Self {
        self.context = ctx.into();
        self
    }
    pub fn usage(mut self, usage: char) -> Self {
        self.usage = usage;
        self
    }
    pub fn template_char(mut self, tmpl: char) -> Self {
        self.template_char = tmpl;
        self
    }
    pub fn scrypt_params(mut self, params: Params) -> Self {
        self.scrypt_params = Some(params);
        self
    }

    /// Consume the builder and generate the password.
    pub fn build(self) -> Result<String> {
        generate_password(
            &self.master_password,
            &self.user,
            &self.site_name,
            self.counter,
            &self.context,
            self.usage,
            self.template_char,
            self.scrypt_params,
        )
    }
}

/// Generate a password using the Master Password algorithm.
///
/// Inputs must be non-empty and `counter` must be at least 1, per the
/// algorithm specification. All length and counter prefixes are written as
/// raw big-endian bytes (`u32::to_be_bytes`), exactly as the reference
/// implementations do; any string data contributes its UTF-8 bytes.
// The flat argument list mirrors the algorithm's parameters; a struct
// would break the published API for no ergonomic gain at the call sites.
#[allow(clippy::too_many_arguments)]
pub fn generate_password(
    master_password: &str,
    user: &str,
    site_name: &str,
    counter: u32,
    context: &str,
    usage: char,
    template_char: char,
    scrypt_params: Option<Params>,
) -> Result<String> {
    if master_password.is_empty() {
        anyhow::bail!("master password must not be empty");
    }
    if user.is_empty() {
        anyhow::bail!("user must not be empty");
    }
    if site_name.is_empty() {
        anyhow::bail!("site name must not be empty");
    }
    if counter < 1 {
        anyhow::bail!("counter must be at least 1");
    }

    let base_seed = *BASE_KEY.get(&usage).ok_or_else(|| anyhow::anyhow!(
        "usage character '{}' not recognized. Valid options: 'a' (Authentication), 'i' (Login), 'r' (Recovery)",
        usage
    ))?;

    let sparam = scrypt_params.unwrap_or_else(default_scrypt_params);

    // Salt = base_seed || byte-length of user (4 raw big-endian bytes) || user
    let user_bytes = user.as_bytes();
    let mut salt = Vec::with_capacity(base_seed.len() + 4 + user_bytes.len());
    salt.extend_from_slice(base_seed.as_bytes());
    salt.extend_from_slice(&(user_bytes.len() as u32).to_be_bytes());
    salt.extend_from_slice(user_bytes);

    let mut master_key = [0u8; 64];
    scrypt(master_password.as_bytes(), &salt, &sparam, &mut master_key)
        .context("scrypt key derivation failed")?;

    // HMAC input = base_seed || byte-length of site (BE u32) || site
    //             || counter (BE u32) [|| byte-length of context (BE u32) || context]
    // The context block is only appended when the context is non-empty.
    let site_bytes = site_name.as_bytes();
    let context_bytes = context.as_bytes();
    let mut site_data = Vec::with_capacity(
        base_seed.len()
            + 8
            + site_bytes.len()
            + if context_bytes.is_empty() {
                0
            } else {
                4 + context_bytes.len()
            },
    );
    site_data.extend_from_slice(base_seed.as_bytes());
    site_data.extend_from_slice(&(site_bytes.len() as u32).to_be_bytes());
    site_data.extend_from_slice(site_bytes);
    site_data.extend_from_slice(&counter.to_be_bytes());
    if !context_bytes.is_empty() {
        site_data.extend_from_slice(&(context_bytes.len() as u32).to_be_bytes());
        site_data.extend_from_slice(context_bytes);
    }

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(&master_key).context("HMAC init failed")?;
    mac.update(&site_data);
    let site_key = mac.finalize().into_bytes();

    let templates_for_set = *TEMPLATES.get(&template_char).ok_or_else(|| anyhow::anyhow!(
        "template '{}' not recognized. Valid: x=extra, l=long, m=medium, s=short, n=name, b=basic, P=passphrase, p=pin",
        template_char
    ))?;
    let idx = (site_key[0] as usize) % templates_for_set.len();
    let template = templates_for_set[idx];

    let mut password = String::with_capacity(template.len());
    for (i, ch) in template.chars().enumerate() {
        let pass_chars = *TEMPLATE_CHARS
            .get(&ch)
            .ok_or_else(|| anyhow::anyhow!("template char '{}' (# {}) not defined", ch, i))?;
        let seed = *site_key
            .get(i + 1)
            .ok_or_else(|| anyhow::anyhow!("site key too short for template at position {}", i))?;
        let c = pass_chars
            .chars()
            .nth(usize::from(seed) % pass_chars.len())
            .ok_or_else(|| anyhow::anyhow!("char selection failed for template char '{}'", ch))?;
        password.push(c);
    }

    Ok(password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_same_inputs_produce_same_outputs() {
        let pw1 =
            generate_password("master", "user", "site", 5, "context", 'a', 'l', None).unwrap();
        let pw2 =
            generate_password("master", "user", "site", 5, "context", 'a', 'l', None).unwrap();
        let pw3 =
            generate_password("master", "user", "site", 5, "context", 'a', 'l', None).unwrap();
        assert_eq!(pw1, pw2);
        assert_eq!(pw2, pw3);
    }

    #[test]
    fn different_counters_produce_different_passwords() {
        let pw1 = generate_password("master", "user", "site", 1, "", 'a', 'x', None).unwrap();
        let pw2 = generate_password("master", "user", "site", 2, "", 'a', 'x', None).unwrap();
        let pw3 = generate_password("master", "user", "site", 3, "", 'a', 'x', None).unwrap();
        assert_ne!(pw1, pw2);
        assert_ne!(pw2, pw3);
        assert_ne!(pw1, pw3);
    }

    #[test]
    fn different_users_produce_different_passwords() {
        let pw1 = generate_password("master", "alice", "site", 1, "", 'a', 'x', None).unwrap();
        let pw2 = generate_password("master", "bob", "site", 1, "", 'a', 'x', None).unwrap();
        assert_ne!(pw1, pw2);
    }

    #[test]
    fn different_sites_produce_different_passwords() {
        let pw1 = generate_password("master", "user", "site1", 1, "", 'a', 'x', None).unwrap();
        let pw2 = generate_password("master", "user", "site2", 1, "", 'a', 'x', None).unwrap();
        assert_ne!(pw1, pw2);
    }

    #[test]
    fn different_master_passwords_produce_different_passwords() {
        let pw1 = generate_password("master1", "user", "site", 1, "", 'a', 'x', None).unwrap();
        let pw2 = generate_password("master2", "user", "site", 1, "", 'a', 'x', None).unwrap();
        assert_ne!(pw1, pw2);
    }

    #[test]
    fn different_contexts_produce_different_passwords() {
        let pw1 = generate_password("master", "user", "site", 1, "ctx1", 'a', 'x', None).unwrap();
        let pw2 = generate_password("master", "user", "site", 1, "ctx2", 'a', 'x', None).unwrap();
        assert_ne!(pw1, pw2);
    }

    #[test]
    fn empty_context_differs_from_non_empty_context() {
        let pw1 = generate_password("master", "user", "site", 1, "", 'a', 'x', None).unwrap();
        let pw2 = generate_password("master", "user", "site", 1, "x", 'a', 'x', None).unwrap();
        assert_ne!(pw1, pw2);
    }

    #[test]
    fn different_usage_types_produce_different_passwords() {
        let pw_auth = generate_password("master", "user", "site", 1, "", 'a', 'x', None).unwrap();
        let pw_login = generate_password("master", "user", "site", 1, "", 'i', 'x', None).unwrap();
        let pw_recovery =
            generate_password("master", "user", "site", 1, "", 'r', 'x', None).unwrap();
        assert_ne!(pw_auth, pw_login);
        assert_ne!(pw_login, pw_recovery);
        assert_ne!(pw_auth, pw_recovery);
    }

    #[test]
    fn invalid_usage_rejected() {
        let err = generate_password("pw", "u", "s", 1, "", 'z', 'x', None).unwrap_err();
        assert!(err
            .to_string()
            .contains("usage character 'z' not recognized"));
        assert!(!is_valid_usage('z'));
        assert!(is_valid_usage('a') && is_valid_usage('i') && is_valid_usage('r'));
    }

    #[test]
    fn invalid_template_rejected() {
        let err = generate_password("pw", "u", "s", 1, "", 'a', 'z', None).unwrap_err();
        assert!(err.to_string().contains("template 'z' not recognized"));
        assert!(!is_valid_template('z'));
        assert!(is_valid_template('x'));
    }

    #[test]
    fn empty_inputs_rejected() {
        let err = generate_password("", "user", "site", 1, "", 'a', 'p', None).unwrap_err();
        assert!(err
            .to_string()
            .contains("master password must not be empty"));
        let err = generate_password("master", "", "site", 1, "", 'a', 'p', None).unwrap_err();
        assert!(err.to_string().contains("user must not be empty"));
        let err = generate_password("master", "user", "", 1, "", 'a', 'p', None).unwrap_err();
        assert!(err.to_string().contains("site name must not be empty"));
    }

    #[test]
    fn zero_counter_rejected() {
        let err = generate_password("master", "user", "site", 0, "", 'a', 'x', None).unwrap_err();
        assert!(err.to_string().contains("counter must be at least 1"));
    }

    #[test]
    fn non_ascii_user_and_site() {
        let pw = generate_password("master", "用户", "站点", 1, "", 'a', 'p', None).unwrap();
        assert_eq!(pw.len(), 4);
        assert!(pw.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn non_ascii_master_password() {
        let pw = generate_password("密码", "user", "site", 1, "", 'a', 'p', None).unwrap();
        assert_eq!(pw.len(), 4);
    }

    #[test]
    fn all_templates_produce_valid_passwords() {
        let templates = ['x', 'l', 'm', 's', 'n', 'b', 'P', 'p'];
        for &tmpl in &templates {
            let pw = generate_password("master", "user", "site", 1, "", 'a', tmpl, None).unwrap();
            assert!(!pw.is_empty());
            assert!(pw.is_ascii());
        }
    }

    #[test]
    fn password_length_by_template() {
        let pw_x = generate_password("master", "user", "site", 1, "", 'a', 'x', None).unwrap();
        let pw_l = generate_password("master", "user", "site", 1, "", 'a', 'l', None).unwrap();
        let pw_m = generate_password("master", "user", "site", 1, "", 'a', 'm', None).unwrap();
        let pw_s = generate_password("master", "user", "site", 1, "", 'a', 's', None).unwrap();
        let pw_p = generate_password("master", "user", "site", 1, "", 'a', 'p', None).unwrap();

        assert_eq!(pw_x.len(), 20);
        assert_eq!(pw_l.len(), 14);
        assert_eq!(pw_m.len(), 8);
        assert_eq!(pw_s.len(), 4);
        assert_eq!(pw_p.len(), 4);
    }

    #[test]
    fn complex_unicode_all_fields() {
        let pw = generate_password("密码", "用户", "站点", 99, "上下文", 'a', 'x', None).unwrap();
        assert_eq!(pw.len(), 20);
    }

    #[test]
    fn very_long_context() {
        let long_context = "a".repeat(1000);
        let pw =
            generate_password("master", "user", "site", 1, &long_context, 'a', 'x', None).unwrap();
        assert_eq!(pw.len(), 20);
    }

    #[test]
    fn very_long_master_password() {
        let long_master = "m".repeat(1000);
        let pw = generate_password(&long_master, "user", "site", 1, "", 'a', 'x', None).unwrap();
        assert_eq!(pw.len(), 20);
    }

    #[test]
    fn high_counter_values() {
        let pw1 = generate_password("master", "user", "site", 100, "", 'a', 'x', None).unwrap();
        let pw2 = generate_password("master", "user", "site", 999, "", 'a', 'x', None).unwrap();
        assert_eq!(pw1.len(), 20);
        assert_eq!(pw2.len(), 20);
        assert_ne!(pw1, pw2);
    }

    // ---- Reference vectors -------------------------------------------------
    //
    // Pinned against an independent reference implementation using the raw
    // big-endian byte layout required by the Master Password specification.
    // These cover byte values >= 0x80 in the length/counter prefixes, which
    // a lossy UTF-8 string conversion silently corrupts.

    #[test]
    fn reference_vector_official_long() {
        // Self-test vector shipped with the reference implementations.
        let pw =
            generate_password("password", "user", "example.com", 1, "", 'a', 'l', None).unwrap();
        assert_eq!(pw, "ZedaFaxcZaso9*");
    }

    #[test]
    fn reference_vector_counter_128() {
        // counter 128 = 0x80 in the last prefix byte.
        let pw =
            generate_password("password", "user", "example.com", 128, "", 'a', 'l', None).unwrap();
        assert_eq!(pw, "Cige0%KexdVagd");
    }

    #[test]
    fn reference_vector_counter_200() {
        // counter 200 = 0xC8 in the last prefix byte.
        let pw =
            generate_password("password", "user", "example.com", 200, "", 'a', 'x', None).unwrap();
        assert_eq!(pw, "l1+0WinX36qlzlG6&ItU");
    }

    #[test]
    fn reference_vector_long_site() {
        // 141-byte site name: the length prefix contains 0x8D.
        let site = format!("example{}{}", "0123456789".repeat(13), ".com");
        assert_eq!(site.len(), 141);
        let pw = generate_password("password", "user", &site, 1, "", 'a', 'l', None).unwrap();
        assert_eq!(pw, "CameLapvReje9?");
    }

    #[test]
    fn reference_vector_long_context() {
        // 129-byte context: the context length prefix contains 0x81.
        let context = format!("ctx{}", "x".repeat(126));
        assert_eq!(context.len(), 129);
        let pw = generate_password(
            "password",
            "user",
            "example.com",
            1,
            &context,
            'a',
            'x',
            None,
        )
        .unwrap();
        assert_eq!(pw, "h9!^JuUmlSuoPSLC0AY5");
    }

    #[test]
    fn reference_vector_unicode_inputs() {
        // Non-ASCII names use their UTF-8 bytes with byte-length prefixes.
        let pw = generate_password("密码", "用户", "站点", 1, "", 'a', 'x', None).unwrap();
        assert_eq!(pw, "A2+gcdWxYzlC9YG%!SBc");
    }
}
