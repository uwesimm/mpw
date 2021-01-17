use hmac::{Hmac, Mac, NewMac};
use human_panic::setup_panic;
use scrypt::{scrypt, ScryptParams};
use sha2::Sha256;
use simple_logger::SimpleLogger;
use std::collections::HashMap;
use structopt::StructOpt;

#[derive(StructOpt)]
struct Opt {
        /// Include path
        #[structopt(short = "t", long = "template", default_value="x")]
        pub template: char,

        #[structopt(short = "c", long = "count", default_value="1")]
        pub count: u32,

        // a=Authenticon, l=Login, r=Recovery
        #[structopt(short = "u", long ="usage",default_value="a")]
        pub usage: char,

        #[structopt(short = "x", long ="context", default_value="")]
        pub context: String,
}

macro_rules! hashmap {
        ($( $key: expr => $val: expr ),*) => {{
             let mut map = ::std::collections::HashMap::new();
             $( map.insert($key, $val); )*
             map
        }}
    }

fn u32AsString(x:u32) -> String {
        let bytes=x.to_be_bytes().to_vec();
        String::from_utf8(bytes).unwrap()
}

fn main() {
        SimpleLogger::new().init().unwrap();
        setup_panic!();

        // taken from https://masterpassword.app/masterpassword-algorithm.pdf
        let templateChars = hashmap![
                ' ' => " ",
                'V' => "AEIOU",
                'C' => "BCDFGHJKLMNPQRSTVWXYZ",
                'v'=> "aeiou",
                'c'=> "bcdfghjklmnpqrstvwxyz",
                'A'=> "AEIOUBCDFGHJKLMNPQRSTVWXYZ",
                'a'=> "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz",
                'n'=> "0123456789",
                'o'=> "@&%?,=[]_:-+*$#!'^~;()/.",
                'x'=> "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()"
        ];

        let templates = hashmap![
                'x' => vec!["anoxxxxxxxxxxxxxxxxx","axxxxxxxxxxxxxxxxxno"],
                'p' => vec!["nnnn"],
                'l' => 
  vec![
                "CvcvnoCvcvCvcv", "CvcvCvcvnoCvcv", "CvcvCvcvCvcvno", "CvccnoCvcvCvcv",
                "CvccCvcvnoCvcv", "CvccCvcvCvcvno", "CvcvnoCvccCvcv", "CvcvCvccnoCvcv",
                "CvcvCvccCvcvno", "CvcvnoCvcvCvcc", "CvcvCvcvnoCvcc", "CvcvCvcvCvccno",
                "CvccnoCvccCvcv", "CvccCvccnoCvcv", "CvccCvccCvcvno", "CvcvnoCvccCvcc",
                "CvcvCvccnoCvcc", "CvcvCvccCvccno", "CvccnoCvcvCvcc", "CvccCvcvnoCvcc",
                "CvccCvcvCvccno"
  ],
              /*  
                vec!["CvcvnoCvcvCvcv","CvcvCvcvCvccno",
                "CvcvCvcvnoCvcv","CvccnoCvccCvcv","CvcvCvcvCvcvno",
                "CvccCvccnoCvcv","CvccnoCvcvCvcv","CvccCvccCvcvno","CvccCvcvnoCvcv",
                "CvcvnoCvccCvcc","CvccCvcvCvcvno","CvcvCvccnoCvcc","CvcvnoCvccCvcv",
                "CvcvCvccCvccno","CvcvCvccnoCvcv","CvccnoCvcvCvcc","CvcvCvccCvcvno",
                "CvccCvcvnoCvcc","CvcvnoCvcvCvcc","CvccCvcvCvccno","CvcvCvcvnoCvcc"],
*/

                'm' => vec!["CvcnoCvc","CvcCvcno"],
                's' => vec!["Cvcn"],
                'n' => vec!["cvccvcvcv"],
                'b' => vec!["aaanaaan","aannaaan","aaannaaa"],
                'P' => vec!["cvcc cvc cvccvcv cvc","cvc cvccvcvcv cvcv","cv cvccv cvc cvcvccv"]
        ];

        let baseKey = hashmap![ 
                'a' => "com.lyndir.masterpassword",
                'i' => "com.lyndir.masterpassword.login",
                'r' => "com.lyndir.masterpassword.answer"
        ];

        let opt = Opt::from_args();

//        println!("{:?}", &opt.template);

        let name = rpassword::read_password_from_tty(Some("user: ")).unwrap();
        let site_name = rpassword::read_password_from_tty(Some("site: ")).unwrap();
        let master_password = rpassword::read_password_from_tty(Some("password: ")).unwrap();

        let counter = opt.count;

        let baseSeed = baseKey.get(&opt.usage).unwrap();

        let sparam = ScryptParams::new(15, 8, 2).unwrap();
        let salt = [
                String::from(*baseSeed),
                u32AsString(name.len() as u32),
                name,
        ]
        .concat();
        let mut master_key = [0u8; 64];
        let result = scrypt(
                master_password.as_bytes(),
                salt.as_bytes(),
                &sparam,
                &mut master_key,
        );

        let context = if opt.context == "" {
                String::from("")
        } else {
                [ u32AsString(opt.context.len() as u32), opt.context].concat()
        };

        let site = [
                String::from(*baseSeed),
                u32AsString(site_name.len() as u32),
                site_name,
                u32AsString(counter as u32),
                context
        ]
        .concat();

        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_varkey(&master_key).unwrap();

        mac.update(site.as_bytes());
        let result = mac.finalize();
        let site_key = result.into_bytes();
 //       println!("{:?}",site_key);

        let templates_for_set = templates.get(&opt.template).unwrap();
        let idx = (site_key[0] as usize) % templates_for_set.len();
        let template = templates_for_set[idx];
 //       println!("template {:?}",template);

        let mut vPW = vec![];
        for i in 0 .. template.len() {
                let passChars = templateChars.get(&(template.chars().nth(i).unwrap())).unwrap();
                let pw = passChars.chars().nth(site_key[i+1] as usize % passChars.len());
//                println!("{:?} {:?} {:?}",i,passChars,pw);
                vPW.push(pw.unwrap());
        }
        let vPW:String=vPW.into_iter().collect();
        println!("pw={}",vPW);
}
