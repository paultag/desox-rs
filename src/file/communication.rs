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

/// Within DESFire, each File is marked with how communication must be done.
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum FileCommunication {
    /// Plain writes are allowed
    Plain = 0x00,

    /// Writes must be CMAC Signed
    Cmac = 0x01,

    /// Writes must be Encrypted
    Encrypted = 0x03,
}

impl FileCommunication {
    /// Parse the wire encoded file communicate as a [FileCommunication]
    ///
    /// 'IoBackendErrorT' is generic here because [Error] requires it, this
    /// function does not conduct any I/O on its own. We will never return an
    /// [Error::IoBackend], so this is purely for sizing/checking.
    pub fn from_u8<IoBackendErrorT>(ft: u8) -> Result<Self, Error<IoBackendErrorT>> {
        Ok(match ft {
            0x00 => Self::Plain,
            0x01 => Self::Cmac,
            0x03 => Self::Encrypted,
            _ => {
                return Err(Error::UnsupportedFileCommunication);
            }
        })
    }

    /// Return the [FileCommunication] as a serialized u8 value, as seen over the wire.
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

// vim: foldmethod=marker
