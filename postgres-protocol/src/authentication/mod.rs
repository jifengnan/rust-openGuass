//! Authentication protocol support.
use md5::{Digest, Md5};
use crypto::sha2::Sha256;
use crypto::digest::Digest as sha256Digest;
use lazy_static::lazy_static;
use ring::hmac::Tag;
use ring::hmac::{self};
use ring::pbkdf2::{self, PBKDF2_HMAC_SHA1};
use std::collections::HashMap;
use std::num::NonZeroU32;
use crate::message::backend::{AuthenticationSha256PasswordBody};

pub mod sasl;

lazy_static! {
    static ref HEX_MAP: HashMap<u8, u8> = {
        let mut map: HashMap<u8, u8> = HashMap::with_capacity(30);
        map.insert(48, 0);
        map.insert(49, 1);
        map.insert(50, 2);
        map.insert(51, 3);
        map.insert(52, 4);
        map.insert(53, 5);
        map.insert(54, 6);
        map.insert(55, 7);
        map.insert(56, 8);
        map.insert(57, 9);
        // A - F
        map.insert(65, 10);
        map.insert(66, 11);
        map.insert(67, 12);
        map.insert(68, 13);
        map.insert(69, 14);
        map.insert(70, 15);
        // a - f
        map.insert(97, 10);
        map.insert(98, 11);
        map.insert(99, 12);
        map.insert(100, 13);
        map.insert(101, 14);
        map.insert(102, 15);

        map
    };
}

const LOOKUP_CHAR: [u8; 16] = [
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102,
];

/// Hashes authentication information in a way suitable for use in response
/// to an `AuthenticationMd5Password` message.
///
/// The resulting string should be sent back to the database in a
/// `PasswordMessage` message.
#[inline]
pub fn md5_hash(username: &[u8], password: &[u8], salt: [u8; 4]) -> String {
    let mut md5 = Md5::new();
    md5.update(password);
    md5.update(username);
    let output = md5.finalize_reset();
    md5.update(format!("{:x}", output));
    md5.update(&salt);
    format!("md5{:x}", md5.finalize())
}

/// Hashes authentication information in a way suitable for use in response
/// to an `AuthenticationSha256PasswordBody` message.
///
/// The resulting string should be sent back to the database in a
/// `PasswordMessage` message.
#[inline]
pub fn sha256_hash(password: &[u8], body: AuthenticationSha256PasswordBody) -> Vec<u8> {
    let salt = to_hex_byte(&body.random64code());
    let salted_password = hash_password(password, NonZeroU32::new(body.server_iteration()).unwrap(), &salt);

    let client_key = get_key_from_hmac(&salted_password, "Client Key".as_bytes());
    let client_key_byte = client_key.as_ref();
    let mut hasher = Sha256::new();
    hasher.input(client_key_byte);
    let mut stored_key: [u8; 32] = [0; 32];
    hasher.result(&mut stored_key);

    let tokenbyte = to_hex_byte(&body.token());

    let hmac_result = get_key_from_hmac(&stored_key, &tokenbyte);
    let h = xor_between_password(
        hmac_result.as_ref(),
        client_key_byte,
        client_key_byte.len(),
    );
    let result = bytes_to_hex(&h);
    result
}


fn bytes_to_hex(h: &[u8]) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::with_capacity(h.len() * 2);
    let mut i = 0;
    while i < h.len() {
        let index = i * 2;
        result.insert(index, LOOKUP_CHAR[(h[i] >> 4) as usize]);
        result.insert(index + 1, LOOKUP_CHAR[(h[i] & 0xF) as usize]);
        i += 1;
    }
    result
}

fn xor_between_password(password1: &[u8], password2: &[u8], length: usize) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::with_capacity(length);
    let mut i = 0;
    while i < length {
        result.insert(i, password1[i] ^ password2[i]);
        i += 1;
    }
    result
}

fn get_key_from_hmac(key: &[u8], data: &[u8]) -> Tag {
    let key2 = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&key2, data);
    tag
}

fn to_hex_byte(hex_char: &[u8]) -> Vec<u8> {
    let mut i = 0;
    let length = hex_char.len() / 2;
    let mut result: Vec<u8> = Vec::with_capacity(length);
    while i < length {
        let index = i * 2;
        result.insert(
            i,
            (HEX_MAP.get(&hex_char[index]).unwrap() << 4)
                | HEX_MAP.get(&hex_char[index + 1]).unwrap(),
        );
        i += 1;
    }

    result
}

fn hash_password(password: &[u8], iterations: NonZeroU32, salt: &[u8]) -> [u8; 32] {
    let mut salted_password = [0u8; 32];
    pbkdf2::derive(
        PBKDF2_HMAC_SHA1,
        iterations,
        salt,
        password,
        &mut salted_password,
    );
    salted_password
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn md5() {
        let username = b"md5_user";
        let password = b"password";
        let salt = [0x2a, 0x3d, 0x8f, 0xe0];

        assert_eq!(
            md5_hash(username, password, salt),
            "md562af4dd09bbb41884907a838a3233294"
        );
    }
}
