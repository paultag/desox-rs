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
    CopyToSlice, Error, Padding,
    crypto::{Backend, BackendEncryptor, Scheme, xor},
    std::ops::{Deref, DerefMut},
};

/// Underlying keying state shared between the host (this library) and the
/// card. This tracks the underlying session key and initialization vector
/// (within the Scheme internal to this type), as well as the derived
/// CMAC signature keys `k1` and `k2`.
pub struct KeyingState<const KEY_SIZE: usize, AlgorithmT>
where
    Scheme<KEY_SIZE, AlgorithmT>: Backend<KEY_SIZE>,
{
    backend: Scheme<KEY_SIZE, AlgorithmT>,
    k1: [u8; KEY_SIZE],
    k2: [u8; KEY_SIZE],
}

impl<const KEY_SIZE: usize, AlgorithmT> KeyingState<KEY_SIZE, AlgorithmT>
where
    Scheme<KEY_SIZE, AlgorithmT>: Backend<KEY_SIZE>,
{
    /// Generate the MiFare CMAC "Short Signature" by taking the first 8 bytes,
    /// no matter what the keylength is under the hood.
    pub fn generate_cmac_short(&mut self, header: &[u8], data: &[&[u8]]) -> [u8; 8] {
        self.generate_cmac(header, data)[..8].try_into().unwrap()
    }

    /// Compute the CMAC for the provided input data (and optional trailer).
    pub fn generate_cmac(&mut self, header: &[u8], data: &[&[u8]]) -> [u8; KEY_SIZE] {
        #[cfg(feature = "tracing")]
        tracing::trace!(
            header = hex::encode(header),
            data = data.iter().map(hex::encode).collect::<String>(),
            "computing cmac"
        );

        let mut working_block = [0u8; KEY_SIZE];

        let (mut data, data_len) = {
            let data_len = data.iter().fold(header.len(), |n, data| n + data.len());
            (
                header.iter().chain(data.iter().flat_map(|v| v.iter())),
                data_len,
            )
        };
        let padded = !data_len.is_multiple_of(KEY_SIZE);

        let mut encryptor = self.encryptor();

        let mut data_n = 0;
        while let Some(n) = (&mut data)
            .take(KEY_SIZE)
            .copied()
            .copy_to_slice(&mut working_block)
        {
            data_n += n;
            if data_n == data_len {
                if padded {
                    Padding::pad(&mut working_block, n);
                    xor(&mut working_block, &self.k2);
                } else {
                    xor(&mut working_block, &self.k1);
                }
                encryptor.encrypt(&mut working_block);
                break;
            }
            encryptor.encrypt(&mut working_block);
        }

        self.set_iv(working_block);

        #[cfg(feature = "tracing")]
        tracing::trace!(cmac = hex::encode(working_block), "computed");

        working_block
    }

    /// Validate the trailing CMAC on the provided message.
    ///
    /// 'IoBackendErrorT' is generic here because [Error] requires it, this
    /// function does not conduct any I/O on its own. We will never return an
    /// [Error::IoBackend], so this is purely for sizing/checking.
    pub fn validate_cmac<'a, IoBackendErrorT>(
        &mut self,
        data: &'a [u8],
        trailer: Option<&[u8]>,
    ) -> Result<&'a [u8], Error<IoBackendErrorT>> {
        if data.len() < 8 {
            return Err(Error::InvalidSignature);
        }
        let (data, read_cmac) = data.split_at(data.len() - 8);
        let computed_cmac = self.generate_cmac_short(data, &[trailer.unwrap_or(&[])]);

        #[cfg(feature = "tracing")]
        tracing::trace!(
            provided_cmac = hex::encode(read_cmac),
            computed_cmac = hex::encode(computed_cmac),
            "checking cmac",
        );

        if read_cmac != computed_cmac {
            return Err(Error::InvalidSignature);
        }
        Ok(data)
    }
}

impl<const KEY_SIZE: usize, AlgorithmT> Deref for KeyingState<KEY_SIZE, AlgorithmT>
where
    Scheme<KEY_SIZE, AlgorithmT>: Backend<KEY_SIZE>,
{
    type Target = Scheme<KEY_SIZE, AlgorithmT>;

    fn deref(&self) -> &Scheme<KEY_SIZE, AlgorithmT> {
        &self.backend
    }
}

impl<const KEY_SIZE: usize, AlgorithmT> DerefMut for KeyingState<KEY_SIZE, AlgorithmT>
where
    Scheme<KEY_SIZE, AlgorithmT>: Backend<KEY_SIZE>,
{
    fn deref_mut(&mut self) -> &mut Scheme<KEY_SIZE, AlgorithmT> {
        &mut self.backend
    }
}

impl KeyingState<8, des::Des> {
    /// Create a new DES [KeyingState]
    pub fn new(key: [u8; 8]) -> Self {
        let (k1, k2) = {
            let session_key = Scheme::<8, des::Des>::new(key);
            session_key.generate_cmac_keys()
        };
        Self {
            k1,
            k2,
            backend: Scheme::<8, _>::new(key),
        }
    }
}

impl KeyingState<16, aes::Aes128> {
    /// Create a new AES-128 [KeyingState]
    pub fn new(key: [u8; 16]) -> Self {
        let (k1, k2) = {
            let session_key = Scheme::<16, aes::Aes128>::new(key);
            session_key.generate_cmac_keys()
        };
        Self {
            k1,
            k2,
            backend: Scheme::<16, _>::new(key),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_capture() {
        let mut ks =
            KeyingState::<16, _>::new(hex!("DE 04 17 85 F5 9C 23 F5 C4 EB A7 EE B7 89 78 55"));

        let cmac = ks.generate_cmac_short(&hex!("CD 01 03 00 00 1C 00 00"), &[]);
        assert_eq!(hex!("EF 93 44 CC 38 E2 A9 F0"), cmac);

        let msg = ks
            .validate_cmac::<()>(&hex!("00 19 AC EF 56 46 0F CA DB"), None)
            .unwrap();
        assert_eq!(&hex!("00"), msg);
    }
}

// vim: foldmethod=marker
