
use std::{collections::HashMap};

use hmac::Hmac;
use hmac::Mac;
use human_panic::setup_panic;
use log::LevelFilter;
use log::{debug, info};
use scrypt::{scrypt, Params};
use sha2::Sha256;
use simple_logger::SimpleLogger;
use structopt::StructOpt;

#[derive(StructOpt)]
struct Opt {
    /// template to use: x-extra,l-long,m-medium,s-short,n-normal,P-passphrase,b-basic
    #[structopt(short = "t", long = "template", default_value = "x")]
    pub template: char,

    /// count
    #[structopt(short = "c", long = "count", default_value = "1")]
    pub count: u32,

    /// a=Authentication, l=Login, r=Recovery
    #[structopt(short = "k", long = "kind", default_value = "a")]
    pub usage: char,

    /// optional context
    #[structopt(short = "x", long = "context", default_value = "")]
    pub context: String,
}

fn u32_as_string(x: u32) -> String {
    let bytes = x.to_be_bytes().to_vec();
    String::from_utf8(bytes).unwrap()
}

fn main() -> Result<(), &'static str> {
    SimpleLogger::new().with_level(LevelFilter::Info).env().init().unwrap();

    setup_panic!();

    // taken from https://masterpassword.app/masterpassword-algorithm.pdf
    let template_chars = HashMap::from([
        (' ', " "),
        ('V', "AEIOU"),
        ('C', "BCDFGHJKLMNPQRSTVWXYZ"),
        ('v', "aeiou"),
        ('c', "bcdfghjklmnpqrstvwxyz"),
        ('A', "AEIOUBCDFGHJKLMNPQRSTVWXYZ"),
        ('a', "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz"),
        ('n', "0123456789"),
        ('o', "@&%?,=[]_:-+*$#!'^~;()/."),
        (
            'x',
            "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()",
        ),
    ]);

    let templates = HashMap::from([
        ('x', vec!["anoxxxxxxxxxxxxxxxxx", "axxxxxxxxxxxxxxxxxno"]),
        ('p', vec!["nnnn"]),
        (
            'l',
            vec![
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
        ),
        ('m', vec!["CvcnoCvc", "CvcCvcno"]),
        ('s', vec!["Cvcn"]),
        ('n', vec!["cvccvcvcv"]),
        ('b', vec!["aaanaaan", "aannaaan", "aaannaaa"]),
        (
            'P',
            vec![
                "cvcc cvc cvccvcv cvc",
                "cvc cvccvcvcv cvcv",
                "cv cvccv cvc cvcvccv",
            ],
        ),
    ]);

    let base_key = HashMap::from([
        ('a', "com.lyndir.masterpassword"),
        ('i', "com.lyndir.masterpassword.login"),
        ('r', "com.lyndir.masterpassword.answer"),
    ]);

    let opt = Opt::from_args();

    debug!("template class {:?}", &opt.template);

    let user = rpassword::prompt_password("user: ").unwrap();
    let master_password = rpassword::prompt_password("password: ").unwrap();
    let site_name = rpassword::prompt_password("site: ").unwrap();

    let counter = opt.count;

    let base_seed = base_key.get(&opt.usage).expect("usage character not recognized");

    let sparam = Params::new(15, 8, 2).unwrap();
    let salt = [
        String::from(*base_seed),
        u32_as_string(user.len() as u32),
        user.clone(),
    ]
    .concat();
    let mut master_key = [0u8; 64];
    let _result = scrypt(
        master_password.as_bytes(),
        salt.as_bytes(),
        &sparam,
        &mut master_key,
    );

    let context = if opt.context == "" {
        String::from("")
    } else {
        [u32_as_string(opt.context.len() as u32), opt.context].concat()
    };

    let site = [
        String::from(*base_seed),
        u32_as_string(site_name.len() as u32),
        site_name.clone(),
        u32_as_string(counter as u32),
        context,
    ]
    .concat();

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(&master_key).unwrap();

    mac.update(site.as_bytes());
    let result = mac.finalize();
    let site_key = result.into_bytes();
    debug!("site seed {:?}", site_key);

    let templates_for_set = templates.get(&opt.template).expect("template not available");
    let idx = (site_key[0] as usize) % templates_for_set.len();
    let template = templates_for_set[idx];
    debug!("selected template {:?}", template);

    let mut v_pw = vec![];
    for i in 0..template.len() {
        let pass_chars = template_chars
            .get(&(template.chars().nth(i).unwrap()))
            .unwrap();
        let pw = pass_chars
            .chars()
            .nth(site_key[i + 1] as usize % pass_chars.len());
        debug!("select char {:?} {:?} {:?}", i, pass_chars, pw);
        v_pw.push(pw.unwrap());
    }
    let v_pw: String = v_pw.into_iter().collect();

    info!("password for user {} and site {} is {}", user, site_name, v_pw);
    Ok(())
}
