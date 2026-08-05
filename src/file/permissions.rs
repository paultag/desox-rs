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

use crate::{Error, KeyId};

/// File permissions
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct FilePermissions {
    /// Permission to change permission key ACLs
    pub change: KeyId,

    /// Permission to read *AND* write to the file.
    pub read_write: KeyId,

    /// Permission to write to the file.
    pub write: KeyId,

    /// Permission to read the file.
    pub read: KeyId,
}

fn kid_to_nibble<IoBackendErrorT>(kid: KeyId) -> Result<u8, Error<IoBackendErrorT>> {
    Ok(match kid {
        0..=14 => kid,
        _ => return Err(Error::BadKeyId),
    })
}

fn nibble_to_kid<IoBackendErrorT>(kid: u8) -> Result<KeyId, Error<IoBackendErrorT>> {
    Ok(match kid {
        0..=14 => kid,
        _ => return Err(Error::BadKeyId),
    })
}

fn byte_to_kids<IoBackendErrorT>(byte: u8) -> Result<(KeyId, KeyId), Error<IoBackendErrorT>> {
    Ok((
        nibble_to_kid(byte & 0x0F)?,
        nibble_to_kid((byte & 0xF0) >> 4)?,
    ))
}

impl FilePermissions {
    /// Parse the wire encoded permissions as a [FilePermissions].
    ///
    /// 'IoBackendErrorT' is generic here because [Error] requires it, this
    /// function does not conduct any I/O on its own. We will never return an
    /// [Error::IoBackend], so this is purely for sizing/checking.
    pub fn from_bytes<IoBackendErrorT>(fp: [u8; 2]) -> Result<Self, Error<IoBackendErrorT>> {
        let [fp1, fp2] = fp;
        let (change, read_write) = byte_to_kids(fp1)?;
        let (write, read) = byte_to_kids(fp2)?;

        Ok(Self {
            change,
            read_write,
            write,
            read,
        })
    }

    /// Return the [FilePermissions] as bytes.
    pub fn as_bytes<IoBackendErrorT>(&self) -> Result<[u8; 2], Error<IoBackendErrorT>> {
        Ok([
            (kid_to_nibble(self.change)? | (kid_to_nibble(self.read_write)? << 4)),
            (kid_to_nibble(self.write)? | (kid_to_nibble(self.read)? << 4)),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_permissions_zero() {
        let fp = FilePermissions::from_bytes::<()>(hex!("00 00")).unwrap();
        assert_eq!(0x00, fp.change);
        assert_eq!(0x00, fp.read_write);
        assert_eq!(0x00, fp.write);
        assert_eq!(0x00, fp.read);
    }

    #[test]
    fn test_permissions_1234() {
        let fp = FilePermissions::from_bytes::<()>(hex!("21 43")).unwrap();
        assert_eq!(0x01, fp.change);
        assert_eq!(0x02, fp.read_write);
        assert_eq!(0x03, fp.write);
        assert_eq!(0x04, fp.read);
        let fp_raw: [u8; 2] = fp.as_bytes::<()>().unwrap();
        assert_eq!([0x21, 0x43], fp_raw);
    }
}

// vim: foldmethod=marker
