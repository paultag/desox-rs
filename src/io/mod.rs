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

//! Underlying traits and helper functions to handle I/O with a DESFire card.

mod cmac;
mod crc;
mod encrypted;
mod mock;
mod plain;

pub use cmac::{cmac_out_cmac_in, plain_out_cmac_in};
pub(crate) use crc::check_crc32;
pub use encrypted::{encrypted_out_cmac_in, encrypted_out_plain_in, plain_out_encrypted_in};
pub use mock::MockBackend;
#[allow(unused_imports)]
pub(crate) use mock::mock_backend;
pub use plain::{plain, plain_multi};

use crate::{
    StatusCode,
    std::{fmt::Debug, future::Future},
};

/// Transport to talk to some DESFire card. This can be whatever is at your
/// disposal -- but usually something like pcscd.
pub trait Backend
where
    Self::Error: Debug,
{
    /// Error type returned by the underlying transport.
    type Error;

    /// Exchange messages with the backend. This will send the data provided in
    /// 'input' to the backend, and the response bytes will be written to
    /// 'output'. The number of bytes written to `output` will be returned.
    fn exchange_raw(
        &self,
        output: &mut [u8],
        input: &[u8],
    ) -> impl Future<Output = Result<usize, Self::Error>>;

    /// Helper function to handle exchanging a single message with the
    /// backend. This will invoke [Self::exchange_raw], split (and parse)
    /// the StatusCode, and return the data returned.
    ///
    /// If you're looking to directly talk to a DESFire card using raw bytes,
    /// this is likely the method you're looking for.
    #[allow(async_fn_in_trait)]
    async fn exchange<'a>(
        &self,
        output: &'a mut [u8],
        input: &[u8],
    ) -> Result<(StatusCode, &'a [u8]), Self::Error> {
        let n = self.exchange_raw(output, input).await?;
        assert!(n > 0);
        let status_code = output[0];
        let data = &output[1..n];
        Ok((status_code.into(), data))
    }
}

impl<T> Backend for &T
where
    T: Backend,
{
    type Error = T::Error;
    async fn exchange_raw(&self, output: &mut [u8], input: &[u8]) -> Result<usize, Self::Error> {
        <T as Backend>::exchange_raw(self, output, input).await
    }
}

impl<T> Backend for &mut T
where
    T: Backend,
{
    type Error = T::Error;
    async fn exchange_raw(&self, output: &mut [u8], input: &[u8]) -> Result<usize, Self::Error> {
        <T as Backend>::exchange_raw(self, output, input).await
    }
}

// vim: foldmethod=marker
