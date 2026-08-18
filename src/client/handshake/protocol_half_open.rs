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

use super::{Handshake, Successful};
use crate::{
    Error,
    crypto::{Backend, Kdf, Scheme},
};

/// Handshake State struct; This indicates that we've started authentication,
/// and have what we believe to be the card-provided 'RndB' value. We have
/// generated our 'RnbB' key, and are awaiting the chip to confirm the
/// key exchange.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct HalfOpen<const KEY_SIZE: usize> {
    pub(super) rnd_a: [u8; KEY_SIZE],
    pub(super) rnd_b: [u8; KEY_SIZE],
}

impl<const KEY_SIZE: usize, AlgorithmT> Handshake<KEY_SIZE, AlgorithmT, HalfOpen<KEY_SIZE>>
where
    Scheme<KEY_SIZE, AlgorithmT>: Backend<KEY_SIZE>,
    ([u8; KEY_SIZE], [u8; KEY_SIZE]): Kdf<KEY_SIZE>,
{
    /// Given the reply from the card to us, process the response such
    /// that we can confirm we share the same session key components
    /// and control of the secret key.
    ///
    /// 'IoBackendErrorT' is generic here because [Error] requires it, this
    /// function does not conduct any I/O on its own. We will never return an
    /// [Error::IoBackend], so this is purely for sizing/checking.
    pub fn complete<IoBackendErrorT>(
        self,
        input: &[u8],
    ) -> Result<Handshake<KEY_SIZE, AlgorithmT, Successful>, Error<IoBackendErrorT>> {
        let Self {
            mut keying,
            state: HalfOpen {
                rnd_a: e_rnd_a,
                rnd_b,
            },
        } = self;

        if input.len() != KEY_SIZE {
            return Err(Error::BadSize);
        }

        let mut plaintext = input.to_vec();
        keying.decrypt(&mut plaintext);
        let mut rnd_a: [u8; KEY_SIZE] = plaintext.try_into().unwrap();
        rnd_a.rotate_right(1);

        if rnd_a != e_rnd_a {
            return Err(Error::InvalidHandshakeResponse);
        }

        // We now have a shared rnd_a/rnd_b; we can derive a Session Key
        // and switch over to it.

        let session_key = (rnd_a, rnd_b).derive();

        #[cfg(feature = "tracing")]
        tracing::debug!(
            session_key = format!("{:02x?}", session_key),
            "authentication successful",
        );

        Ok(Handshake {
            keying: Scheme::<KEY_SIZE, AlgorithmT>::new(session_key),
            state: Successful,
        })
    }
}

// vim: foldmethod=marker
