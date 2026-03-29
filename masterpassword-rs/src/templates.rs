use phf::phf_map;

/// Base keys for the Master Password algorithm.
/// Values from https://github.com/Lyndir/masterpassword/blob/master/lib/masterpassword.py
pub static BASE_KEY: phf::Map<char, &'static str> = phf_map! {
    'a' => "com.lyndir.masterpassword",
    'i' => "com.lyndir.masterpassword.login",
    'r' => "com.lyndir.masterpassword.answer",
};

/// Mapping from template characters to the allowed character sets.
pub static TEMPLATE_CHARS: phf::Map<char, &'static str> = phf_map! {
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

/// Password templates for each template character.
pub static TEMPLATES: phf::Map<char, &'static [&'static str]> = phf_map! {
    'x' => &["anoxxxxxxxxxxxxxxxxx", "axxxxxxxxxxxxxxxxxno"],
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
