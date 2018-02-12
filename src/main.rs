use std::io::Error;

extern crate num_bigint;
/// Vector of bytes.
pub type Bytes = Vec<u8>;

extern crate rustc_hex;
use rustc_hex::FromHex;

extern crate rand;
use rand::{Rng,OsRng};

extern crate crypto;
extern crate crypto as rcrypto;


/// AES encryption
mod aes {
    use rcrypto::blockmodes::{CtrMode, CbcDecryptor, PkcsPadding};
    use rcrypto::aessafe::{AesSafe128Encryptor, AesSafe128Decryptor};
    use rcrypto::symmetriccipher::{Encryptor, Decryptor, SymmetricCipherError};
    use rcrypto::buffer::{RefReadBuffer, RefWriteBuffer, WriteBuffer};

    /// Encrypt a message (CTR mode)
    pub fn encrypt(k: &[u8], iv: &[u8], plain: &[u8], dest: &mut [u8]) {
        let mut encryptor = CtrMode::new(AesSafe128Encryptor::new(k), iv.to_vec());
        encryptor.encrypt(&mut RefReadBuffer::new(plain), &mut RefWriteBuffer::new(dest), true).expect("Invalid length or padding");
    }

    /// Decrypt a message (CTR mode)
    pub fn decrypt(k: &[u8], iv: &[u8], encrypted: &[u8], dest: &mut [u8]) {
        let mut encryptor = CtrMode::new(AesSafe128Encryptor::new(k), iv.to_vec());
        encryptor.decrypt(&mut RefReadBuffer::new(encrypted), &mut RefWriteBuffer::new(dest), true).expect("Invalid length or padding");
    }


    /// Decrypt a message using cbc mode
    pub fn decrypt_cbc(k: &[u8], iv: &[u8], encrypted: &[u8], dest: &mut [u8]) -> Result<usize, SymmetricCipherError> {
        let mut encryptor = CbcDecryptor::new(AesSafe128Decryptor::new(k), PkcsPadding, iv.to_vec());
        let len = dest.len();
        let mut buffer = RefWriteBuffer::new(dest);
        encryptor.decrypt(&mut RefReadBuffer::new(encrypted), &mut buffer, true)?;
        Ok(len - buffer.remaining())
    }
}

/// Initialization vector length.
const INIT_VEC_LEN: usize = 16;


fn into_document_key(key: Bytes) -> Result<Bytes, Error> {
    // key is a previously distributely generated Public
    // use x coordinate of distributely generated point as encryption key
    Ok(key[..INIT_VEC_LEN].into())
}

fn initialization_vector() -> [u8; INIT_VEC_LEN] {
    let mut result = [0u8; INIT_VEC_LEN];
    let mut rng = OsRng::new().unwrap();
    rng.fill_bytes(&mut result);
    result
}

/// Encrypt document with distributely generated key.
#[no_mangle]
pub extern "C" fn encrypt_document(key: Bytes, document: Bytes) -> Result<Bytes, Error> {
    // make document key
    let key = into_document_key(key)?;

    // use symmetric encryption to encrypt document
    let iv = initialization_vector();
    let mut encrypted_document = vec![0; document.len() + iv.len()];
    {
        let (mut encryption_buffer, iv_buffer) = encrypted_document.split_at_mut(document.len());

        aes::encrypt(&key, &iv, &document, &mut encryption_buffer);
        iv_buffer.copy_from_slice(&iv);
    }

    Ok(encrypted_document)
}

/// Decrypt document with distributely generated key.
#[no_mangle]
pub extern "C" fn decrypt_document(key: Bytes, mut encrypted_document: Bytes) -> Result<Bytes, Error> {
    // initialization vector takes INIT_VEC_LEN bytes
    let encrypted_document_len = encrypted_document.len();

    // make document key
    let key = into_document_key(key)?;

    // use symmetric decryption to decrypt document
    let iv = encrypted_document.split_off(encrypted_document_len - INIT_VEC_LEN);
    let mut document = vec![0; encrypted_document_len - INIT_VEC_LEN];
    aes::decrypt(&key, &iv, &encrypted_document, &mut document);

    Ok(document)
}

#[no_mangle]
pub extern "C" fn add_one(x: i32) -> i32 {
    x + 1
}

fn main() {
    println!("----- Hello, dev's! -----");

    let document_key: Bytes = "cac6c205eb06c8308d65156ff6c862c62b000b8ead121a4455a8ddeff7248128d895692136f240d5d1614dc7cc4147b1bd584bd617e30560bb872064d09ea325".from_hex().unwrap();
    let document: Bytes = b"Hello, world!!!"[..].into();
    println!("Document [as hex] : {:?}", document);

    let encrypted_document = encrypt_document(document_key.clone(), document.clone()).unwrap();
    let decrypted_document = decrypt_document(document_key.clone(), encrypted_document.clone()).unwrap();

    println!("Encrypted document: {:?}  decrypted: {:?}", encrypted_document, decrypted_document);
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
