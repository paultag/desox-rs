// {{{ Copyright (c) Paul R. Tagliamonte <paultag@gmail.com>, 2026
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE. }}}

use crate::{
    crypto::{Backend, BackendDecryptor, BackendEncryptor},
    std::marker::PhantomData,
};
use des::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};

/// Holds the state of the cryptographic session
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Scheme<const BLOCK_SIZE: usize, AlgorithmT> {
    key: [u8; BLOCK_SIZE],
    iv: [u8; BLOCK_SIZE],
    _algorithm: PhantomData<AlgorithmT>,
}

macro_rules! impl_crypto_backend {
    ($key_size:literal, $crypto:path, $cmac_type:ident($r_b:literal)) => {
        impl BackendEncryptor<$key_size> for cbc::Encryptor<$crypto> {
            fn encrypt(&mut self, data: &mut [u8]) {
                #[cfg(feature = "tracing")]
                tracing::trace!(data = hex::encode(&data), "encrypting");
                let (data_chunks, data_leftover) = data.as_chunks_mut::<$key_size>();
                assert!(data_leftover.is_empty()); // ensure block alignment
                for data in data_chunks {
                    self.encrypt_block(data.into());
                }
                #[cfg(feature = "tracing")]
                tracing::trace!(data = hex::encode(&data), "encrypted");
            }
        }

        impl BackendDecryptor<$key_size> for cbc::Decryptor<$crypto> {
            fn decrypt(&mut self, data: &mut [u8]) {
                #[cfg(feature = "tracing")]
                tracing::trace!(data = hex::encode(&data), "decrypting");
                let (data_chunks, data_leftover) = data.as_chunks_mut::<$key_size>();
                assert!(data_leftover.is_empty()); // ensure block alignment
                for data in data_chunks {
                    self.decrypt_block(data.into());
                }
                #[cfg(feature = "tracing")]
                tracing::trace!(data = hex::encode(&data), "decrypted");
            }
        }

        impl Backend<$key_size> for Scheme<$key_size, $crypto> {
            type Encryptor = cbc::Encryptor<$crypto>;
            type Decryptor = cbc::Decryptor<$crypto>;

            fn new(key: [u8; $key_size]) -> Self {
                Self {
                    key,
                    iv: Default::default(),
                    _algorithm: PhantomData,
                }
            }

            fn get_key(&self) -> &[u8; $key_size] {
                &self.key
            }

            fn get_iv(&self) -> &[u8; $key_size] {
                &self.iv
            }

            fn set_iv(&mut self, iv: [u8; $key_size]) {
                #[cfg(feature = "tracing")]
                tracing::trace!(iv = hex::encode(iv), "iv updated",);
                self.iv = iv
            }

            fn decryptor(&self) -> cbc::Decryptor<$crypto> {
                #[cfg(feature = "tracing")]
                tracing::trace!(
                    key = hex::encode(self.key),
                    iv = hex::encode(self.iv),
                    "new decryptor"
                );
                cbc::Decryptor::<$crypto>::new((&self.key).into(), (&self.iv).into())
            }

            fn encryptor(&self) -> cbc::Encryptor<$crypto> {
                #[cfg(feature = "tracing")]
                tracing::trace!(
                    key = hex::encode(self.key),
                    iv = hex::encode(self.iv),
                    "new encryptor",
                );
                cbc::Encryptor::<$crypto>::new((&self.key).into(), (&self.iv).into())
            }

            fn generate_cmac_keys(mut self) -> ([u8; $key_size], [u8; $key_size]) {
                let mut mac = [0; $key_size];
                self.encrypt(&mut mac);

                fn shift_xor(mac: &mut [u8; $key_size]) {
                    let x = if mac[0] & 0x80 != 0 { $r_b } else { 0x00 };
                    *mac = (($cmac_type::from_be_bytes(*mac) << 1) ^ x).to_be_bytes()
                }

                let mut k1 = mac;
                shift_xor(&mut k1);

                let mut k2 = k1;
                shift_xor(&mut k2);

                #[cfg(feature = "tracing")]
                tracing::trace!(
                    k1 = hex::encode(k1),
                    k2 = hex::encode(k2),
                    "cmac keys generated",
                );

                (k1, k2)
            }
        }
    };
}

impl_crypto_backend!(8, des::Des, u64(0x1B));
impl_crypto_backend!(16, aes::Aes128, u128(0x87));

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::xor;
    use hex_literal::hex;

    fn _test_simple_round_trip<const BLOCK_SIZE: usize, AlgorithmT>(
        backend: &mut Scheme<BLOCK_SIZE, AlgorithmT>,
    ) where
        Scheme<BLOCK_SIZE, AlgorithmT>: Backend<BLOCK_SIZE>,
    {
        let ciphertext = {
            let mut out = vec![0xFA; BLOCK_SIZE * 10];
            backend.set_iv([0xEE; BLOCK_SIZE]);
            backend.encrypt(&mut out);
            out
        };

        let plaintext = {
            let mut out = ciphertext.clone();
            backend.set_iv([0xEE; BLOCK_SIZE]);
            backend.decrypt(&mut out);
            out
        };

        assert_eq!(vec![0xFA; BLOCK_SIZE * 10], plaintext);
    }

    #[test]
    fn test_des() {
        let mut backend = Scheme::<8, _>::new([0x0A; 8]);
        _test_simple_round_trip::<8, des::Des>(&mut backend);
    }

    #[test]
    fn test_aes128() {
        let mut backend = Scheme::<16, _>::new([0x0A; 16]);
        _test_simple_round_trip::<16, aes::Aes128>(&mut backend);
    }

    #[test]
    fn test_cmac_example() {
        let session_key = Scheme::<8, des::Des>::new(hex!("BA 02 0A 16 EC E6 1C 12"));
        let ref_k1 = hex!("6E DE 5E 90 97 B9 4D 7B");
        let ref_k2 = hex!("DD BC BD 21 2F 72 9A F6");

        let (k1, k2) = session_key.generate_cmac_keys();

        assert_eq!(ref_k1, k1);
        assert_eq!(ref_k2, k2);
    }

    #[test]
    fn test_fc_example() {
        let (_k1, k2) = {
            let session_key = Scheme::<8, des::Des>::new(hex!("BA 02 0A 16 EC E6 1C 12"));
            session_key.generate_cmac_keys()
        };

        let mut session_key = Scheme::<8, des::Des>::new(hex!("BA 02 0A 16 EC E6 1C 12"));
        let mut command = hex!("FC 80 00 00 00 00 00 00");
        xor(&mut command, &k2);
        assert_eq!(hex!("21 3C BD 21 2F 72 9A F6"), command);
        session_key.encrypt(&mut command);
        assert_eq!(hex!("32 40 EA F7 61 94 1C DF"), command);
    }

    #[test]
    fn test_cmac_example_aes() {
        let session_key =
            Scheme::<16, aes::Aes128>::new(hex!("DE 04 17 85 F5 9C 23 F5 C4 EB A7 EE B7 89 78 55"));

        let (k1, k2) = session_key.generate_cmac_keys();

        assert_eq!(hex!("A4 CB 75 45 67 A6 B7 8B 1A 89 21 C9 F8 BF D2 F4"), k1);
        assert_eq!(hex!("49 96 EA 8A CF 4D 6F 16 35 12 43 93 F1 7F A5 6F"), k2);
    }
}

// vim: foldmethod=marker
