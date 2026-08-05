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

use crate::{Error, crc32};

/// Given some input buffer with 4 bytes of CRC-32 at the end, compute
/// the CRC32 of the data (including, optionally, a "trailing" set of
/// data after the input buffer's data), and compare the computed CRC32
/// to the received CRC32.
///
/// 'IoBackendErrorT' is generic here because [Error] requires it, this
/// function does not conduct any I/O on its own. We will never return an
/// [Error::IoBackend], so this is purely for sizing/checking.
pub fn check_crc32<'a, IoBackendErrorT>(
    input: &'a [u8],
    trailers: &[&[u8]],
) -> Result<&'a [u8], Error<IoBackendErrorT>> {
    let (message, read_crc32) = input.split_at(input.len() - 4);
    let read_crc32: [u8; 4] = read_crc32.try_into().unwrap();
    let read_crc32 = u32::from_le_bytes(read_crc32);

    let gen_crc32 = crc32(message, trailers);

    if read_crc32 != gen_crc32 {
        return Err(Error::InvalidCrc32);
    }
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_check() {
        check_crc32::<()>(b"Hello, World! This is a test\x55\xA7\xB5\x6F", &[&[0x00]]).unwrap();
    }
}

// vim: foldmethod=marker
