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

/// Compute the DESFire CRC32 flavor. This also takes an optional "trailer",
/// which is the same as checksumming a contiguous block of data containing
/// the concatanation.
pub(crate) fn crc32(message: &[u8], trailers: &[&[u8]]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(message);
    for trailer in trailers {
        hasher.update(trailer);
    }
    0xFFFFFFFF - hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_crc32() {
        assert_eq!(
            hex!("55 A7 B5 6F"),
            crc32(b"Hello, World! This is a test", &[&[0x00]]).to_le_bytes(),
        )
    }
}

// vim: foldmethod=marker
