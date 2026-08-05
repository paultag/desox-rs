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

//! DESFire-specific cryptographic building blocks.

mod backend;
mod kdf;
mod scheme;

pub use backend::{Backend, BackendDecryptor, BackendEncryptor};
pub use kdf::Kdf;
pub use scheme::Scheme;

/// XOR a buffer with a key (usually a CMAC derived key).
pub fn xor<const BLOCK_SIZE: usize>(buf: &mut [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) {
    buf.iter_mut()
        .zip(key.iter())
        .for_each(|(buf, key)| *buf ^= *key);
}

// vim: foldmethod=marker
