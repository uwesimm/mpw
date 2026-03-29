use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use scrypt::{scrypt, Params};
use sha2::Sha256;

use crate::templates::{BASE_KEY, TEMPLATE_CHARS, TEMPLATES};

/// Convert a u32 to a 4‑byte big‑endian string.
pub(crate) pub(crate) fn u32_as_string(x: u32) -> String {
    // Use lossless conversion; invalid UTF‑8 bytes become the Unicode replacement character.
    String::from_utf8_lossy(&x.to_be_bytes()).into_owned()
}

/// Builder for password generation – provides a more ergonomic API.
#[derive(Debug, Default)]
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

impl PasswordBuilder {
    /// Create a new builder with the three required fields.
    pub fn new(master_password: impl Into<String>, user: impl Into<String>, site_name: impl Into<String>) -> Self {
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
    let base_seed = *BASE_KEY.get(&usage).ok_or_else(|| anyhow::anyhow!(
        "usage character '{}' not recognized. Valid options: 'a' (Authentication), 'i' (Login), 'r' (Recovery)",
        usage
    ))?;

    let sparam = match scrypt_params {
        Some(p) => p,
        None => Params::new(15, 8, 2, 64).context("invalid scrypt params")?,
    };

    let salt = [
        String::from(base_seed),
        u32_as_string(user.len() as u32),
        user.to_string(),
    ]
    .concat();
    let mut master_key = [0u8; 64];
    let _ = scrypt(master_password.as_bytes(), salt.as_bytes(), &sparam, &mut master_key);

    let ctx = if context.is_empty() {
        String::new()
    } else {
        format!("{}{}", u32_as_string(context.len() as u32), context)
    };

    let site = [
        String::from(base_seed),
        u32_as_string(site_name.len() as u32),
        site_name.to_string(),
        u32_as_string(counter),
        ctx,
    ]
    .concat();

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(&master_key).context("HMAC init failed")?;
    mac.update(site.as_bytes());
    let result = mac.finalize();
    let site_key = result.into_bytes();

    let templates_for_set = *TEMPLATES.get(&template_char).ok_or_else(|| anyhow::anyhow!(
        "template '{}' not recognized. Valid: x=extra, l=long, m=medium, s=short, n=name, b=basic, P=passphrase, p=pin",
        template_char
    ))?;
    let idx = (site_key[0] as usize) % templates_for_set.len();
    let template = templates_for_set[idx];

    let mut v_pw = Vec::with_capacity(template.len());
    for i in 0..template.len() {
        let ch = template.chars().nth(i).unwrap();
        let pass_chars = *TEMPLATE_CHARS.get(&ch).ok_or_else(|| anyhow::anyhow!("template char #{} not defined", i))?;
        let pw = pass_chars.chars().nth(site_key[i + 1] as usize % pass_chars.len());
        v_pw.push(pw.ok_or_else(|| anyhow::anyhow!("char selection none"))?);
    }

    Ok(v_pw.into_iter().collect())
}
