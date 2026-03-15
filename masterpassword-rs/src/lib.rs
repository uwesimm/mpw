use anyhow::Context;
use hmac::Hmac;
use hmac::Mac;
use scrypt::{scrypt, Params};
use sha2::Sha256;
use anyhow::Result;
use phf::phf_map;
use log::debug;

static BASE_KEY: phf::Map<char, &'static str> = phf_map! {
    'a' => "com.lyndir.masterpassword",
    'i' => "com.lyndir.masterpassword.login",
    'r' => "com.lyndir.masterpassword.answer",
};

static TEMPLATE_CHARS: phf::Map<char, &'static str> = phf_map! {
    ' ' => " ",
    'V' => "AEIOU",
    'C' => "BCDFGHJKLMNPQRSTVWXYZ",
    'v' => "aeiou",
    'c' => "bcdfghjklmnpqrstvwxyz",
    'A' => "AEIOUBCDFGHJKLMNPQRSTVWXYZ",
    'a' => "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz",
    'n' => "0123456789",
    'o' => "@&%?,=[]_:-+*$#!'^~;()/.",
    'x' => "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()",
};

// Vowels, Consonants, vovels, consonants, Alphabetic, alphabetic, numeric,other,X all
static TEMPLATES: phf::Map<char, &'static [&'static str]> = phf_map! {
    'x' => &[
        "anoxxxxxxxxxxxxxxxxx",
        "axxxxxxxxxxxxxxxxxno",
    ],
    'p' => &["nnnn"],
    'l' => &[
        "CvcvnoCvcvCvcv",
        "CvcvCvcvnoCvcv",
        "CvcvCvcvCvcvno",
        "CvccnoCvcvCvcv",
        "CvccCvcvnoCvcv",
        "CvccCvcvCvcvno",
        "CvcvnoCvccCvcv",
        "CvcvCvccnoCvcv",
        "CvcvCvccCvcvno",
        "CvcvnoCvcvCvcc",
        "CvcvCvcvnoCvcc",
        "CvcvCvcvCvccno",
        "CvccnoCvccCvcv",
        "CvccCvccnoCvcv",
        "CvccCvccCvcvno",
        "CvcvnoCvccCvcc",
        "CvcvCvccnoCvcc",
        "CvcvCvccCvccno",
        "CvccnoCvcvCvcc",
        "CvccCvcvnoCvcc",
        "CvccCvcvCvccno",
    ],
    'm' => &["CvcnoCvc", "CvcCvcno"],
    's' => &["Cvcn"],
    'n' => &["cvccvcvcv"],
    'b' => &["aaanaaan", "aannaaan", "aaannaaa"],
    'P' => &[
        "cvcc cvc cvccvcv cvc",
        "cvc cvccvcvcv cvcv",
        "cv cvccv cvc cvcvccv",
    ],
};

fn u32_as_string(x: u32) -> String {
    let bytes = x.to_be_bytes().to_vec();
    String::from_utf8(bytes).unwrap()
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
    let base_seed = *BASE_KEY.get(&usage).ok_or_else(|| anyhow::anyhow!("usage character not recognized"))?;

    let sparam = match scrypt_params {
        Some(p) => p,
        None => Params::new(15, 8, 2, 64).context("invalid scrypt params")?,
    };

    let salt = [String::from(base_seed), u32_as_string(user.len() as u32), user.to_string()].concat();
    let mut master_key = [0u8; 64];
    let _ = scrypt(master_password.as_bytes(), salt.as_bytes(), &sparam, &mut master_key);

    let ctx = if context.is_empty() { String::new() } else { format!("{}{}", u32_as_string(context.len() as u32), context) };

    let site = [String::from(base_seed), u32_as_string(site_name.len() as u32), site_name.to_string(), u32_as_string(counter), ctx].concat();

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(&master_key).context("HMAC init failed")?;
    mac.update(site.as_bytes());
    let result = mac.finalize();
    let site_key = result.into_bytes();
    debug!("site seed {:?}", site_key);

    let templates_for_set = *TEMPLATES.get(&template_char).ok_or_else(|| anyhow::anyhow!("template not available"))?;
    let idx = (site_key[0] as usize) % templates_for_set.len();
    let template = templates_for_set[idx];
    debug!("selected template {:?}", template);

    let mut v_pw = Vec::with_capacity(template.len());
    for i in 0..template.len() {
        let ch = template.chars().nth(i).unwrap();
        let pass_chars = *TEMPLATE_CHARS.get(&ch).ok_or_else(|| anyhow::anyhow!("template char #i not defined"))?;
        let pw = pass_chars.chars().nth(site_key[i + 1] as usize % pass_chars.len());
        debug!("select char {:?} {:?} {:?}", i, pass_chars, pw);
        v_pw.push(pw.ok_or_else(|| anyhow::anyhow!("char selection none"))?);
    }

    Ok(v_pw.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u32_as_string_small_values() {
        for &x in &[0u32, 1u32, 3u32, 127u32] {
            let s = u32_as_string(x);
            assert_eq!(s.as_bytes(), &x.to_be_bytes());
        }
    }

    #[test]
    fn deterministic_small_params() {
        let params = Params::new(8, 1, 1, 64).unwrap();
        let pw1 = generate_password("password", "bob", "mysite", 1, "", 'a', 'p', Some(params)).unwrap();
        let pw2 = generate_password("password", "bob", "mysite", 1, "", 'a', 'p', Some(Params::new(8, 1, 1, 64).unwrap())).unwrap();
        assert_eq!(pw1, pw2);
        assert_eq!(pw1.len(), 4);
        assert!(pw1.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn full_mpw() {
        let pw1 = generate_password("1", "1", "1", 1, "", 'a', 'x', None).unwrap();
        assert_eq!(pw1, "FLCUCf7B7TqqT*7Qdk8&");
    }
}
