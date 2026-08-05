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

use crate::Error;

/// Number (and type) of keys. If no specific Application has been selected,
/// this will return information about the PICC Key. If a specific Application
/// has been selected, this will return the number and type of keys present
/// in the current application.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum KeyCount {
    /// Number of DES keys
    Des(u8),

    ///  Number of AES keys
    Aes(u8),
}

impl KeyCount {
    /// Return the [KeyCount] as a serialized u8 value, as seen over the wire.
    ///
    /// 'IoBackendErrorT' is generic here because [Error] requires it, this
    /// function does not conduct any I/O on its own. We will never return an
    /// [Error::IoBackend], so this is purely for sizing/checking.
    pub fn as_u8<IoBackendErrorT>(&self) -> Result<u8, Error<IoBackendErrorT>> {
        Ok(match self {
            KeyCount::Des(v @ 1..=14) => *v,
            KeyCount::Aes(v @ 1..=14) => *v | 0x80,
            _ => return Err(Error::BadKeyId),
        })
    }

    /// Parse the wire encoded key count as a [KeyCount].
    ///
    /// 'IoBackendErrorT' is generic here because [Error] requires it, this
    /// function does not conduct any I/O on its own. We will never return an
    /// [Error::IoBackend], so this is purely for sizing/checking.
    pub fn from_u8<IoBackendErrorT>(kc: u8) -> Result<Self, Error<IoBackendErrorT>> {
        let count = kc & 0x0F;
        let type_ = kc & 0xF0;

        match (type_, count) {
            (0x00, 1..=14) => Ok(Self::Des(count)),
            (0x80, 1..=14) => Ok(Self::Aes(count)),
            (0x00, _) => Err(Error::BadKeyId),
            (0x80, _) => Err(Error::BadKeyId),
            (_, _) => Err(Error::UnsupportedAlgorithm),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_des_count() {
        for count_in in 1..=14 {
            let count_out = KeyCount::Des(count_in).as_u8::<()>().unwrap();
            assert_eq!(count_in, count_out);
        }
        for count_in in 15..=255 {
            assert!(KeyCount::Des(count_in).as_u8::<()>().is_err());
        }
    }

    #[test]
    fn every_aes_count() {
        for count_in in 1..=14 {
            let count_out = KeyCount::Aes(count_in).as_u8::<()>().unwrap();
            assert_eq!(count_in | 0x80, count_out);
        }
        for count_in in 15..=255 {
            assert!(KeyCount::Aes(count_in).as_u8::<()>().is_err());
        }
    }

    #[test]
    fn every_aes_round_trip() {
        for count_in in 1..=14 {
            let count_in = count_in | 0x80;
            let count = KeyCount::from_u8::<()>(count_in).unwrap();
            let count_out = count.as_u8::<()>().unwrap();
            assert_eq!(count_in, count_out);
        }
        for count_in in &[0, 15] {
            let count_in = count_in | 0x80;
            assert!(KeyCount::from_u8::<()>(count_in).is_err());
        }
    }

    #[test]
    fn every_des_round_trip() {
        for count_in in 1..=14 {
            let count = KeyCount::from_u8::<()>(count_in).unwrap();
            let count_out = count.as_u8::<()>().unwrap();
            assert_eq!(count_in, count_out);
        }
        for count_in in [0u8, 15] {
            assert!(KeyCount::from_u8::<()>(count_in).is_err());
        }
    }
}

// vim: foldmethod=marker
