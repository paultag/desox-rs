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

use crate::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt, Error};

/// Wrapper around some [tokio::io::AsyncRead] and [tokio::io::AsyncWrite]
/// traited object that implements a (very!) basic APDU transport for use
/// with DESOx.
///
/// Messages over the transport are length-prefixed using a u8 to indicate
/// the number of bytes to follow. Since the DESFire card can only take a max
/// of 60 bytes, we can store the length of the APDU message in a u8 without
/// worrying too much about it.
pub struct TransportBackend<TransportT>(TransportT)
where
    TransportT: AsyncReadExt,
    TransportT: AsyncWriteExt,
    TransportT: Unpin;

impl<TransportT> io::Backend for TransportBackend<TransportT>
where
    TransportT: AsyncReadExt,
    TransportT: AsyncWriteExt,
    TransportT: Unpin,
{
    type Error = Error;

    async fn exchange_raw(&mut self, response: &mut [u8], request: &[u8]) -> Result<usize, Error> {
        let stream = &mut self.0;

        let size = request.len() as u8;
        stream.write_u8(size).await?;
        stream.write_all(request).await?;
        let size = stream.read_u8().await? as usize;
        stream.read_exact(&mut response[..size]).await?;
        Ok(size)
    }
}

impl<TransportT> TransportBackend<TransportT>
where
    TransportT: AsyncReadExt,
    TransportT: AsyncWriteExt,
    TransportT: Unpin,
{
    /// Create a new [TransportBackend]
    pub fn new(transport: TransportT) -> Self {
        Self(transport)
    }

    /// Create a new [TransportBackend]
    pub fn into_inner(self) -> TransportT {
        self.0
    }
}

// vim: foldmethod=marker
