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

/// DESFire specific padding scheme. This isn't quite as ... robust ... as
/// other padding schemes because there's a fair amount of ambiguity in when
/// to pad.
///
/// DESFire padding is done by filling the remaining block-aligned space
/// with zeros, and the first byte past the real data set to 0x80. This means
/// you can unpad by reading 0x00 from the end until you hit a 0x80, and return
/// all prior bytes.
///
/// However, messages aren't *ALWAYS* padded - if the data is already block
/// aligned, no padding is added, so there's no REAL way to tell if the data
/// ends with 0x80 or 0x80 0x00 vs having been padded.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Padding;

impl Padding {
    /// Apply DESFire-specific padding to the data buffer, which is filled with
    /// data up to 'pos'.
    pub fn pad(block: &mut [u8], pos: usize) {
        if pos > block.len() {
            panic!("`pos` is bigger than block size");
        }
        block[pos..].fill(0);
        block[pos] = 0x80;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbc::cipher::{Array, consts::U16};

    #[test]
    fn test_padding() {
        let mut v: Array<u8, U16> = [0; 16].into();
        v[..11].copy_from_slice(b"HELLO WORLD");
        Padding::pad(&mut v, 11);
        assert_eq!(*b"HELLO WORLD\x80\x00\x00\x00\x00", *v);
    }

    #[test]
    fn test_padding_max() {
        let mut v: Array<u8, U16> = [0; 16].into();
        v[..11].copy_from_slice(b"HELLO WORLD");
        Padding::pad(&mut v, 15);
        assert_eq!(*b"HELLO WORLD\x00\x00\x00\x00\x80", *v);
    }

    #[should_panic]
    #[test]
    fn test_padding_overlong() {
        let mut v: Array<u8, U16> = [0; 16].into();
        v[..11].copy_from_slice(b"HELLO WORLD");
        Padding::pad(&mut v, 30);
        assert_eq!(*b"HELLO WORLD\x80\x00\x00\x00\x00", *v);
    }
}

// vim: foldmethod=marker
