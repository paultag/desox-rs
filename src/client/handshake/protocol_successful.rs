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

use super::Handshake;
use crate::crypto::{Backend, Scheme};

/// Handshake State struct; This indicates that the handshake is successful and
/// the underlying key state is valid, and keyed with a shared session-specific
/// encryption key.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Successful;

impl<const KEY_SIZE: usize, AlgorithmT> Handshake<KEY_SIZE, AlgorithmT, Successful>
where
    Scheme<KEY_SIZE, AlgorithmT>: Backend<KEY_SIZE>,
{
    /// Complete the authentication flow
    pub fn into_crypto_scheme(self) -> Scheme<KEY_SIZE, AlgorithmT> {
        let Self { keying, state: _ } = self;
        keying
    }

    /// Complete the authentication flow
    pub fn into_key(self) -> [u8; KEY_SIZE] {
        *self.into_crypto_scheme().get_key()
    }
}

// vim: foldmethod=marker
