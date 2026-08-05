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

use super::Backend;
use crate::std::{
    convert::Infallible,
    sync::atomic::{AtomicU32, Ordering},
};

/// The [MockBackend] implements an [Backend] which comes pre-loaded with
/// the expected response from a card.
#[derive(Debug)]
pub struct MockBackend<'a> {
    responses: &'a [(&'a [u8], &'a [u8])],
    step: AtomicU32,
}

impl<'a> MockBackend<'a> {
    /// Create a new [MockBackend] pre-loaded with the provided message
    pub fn new(responses: &'a [(&'a [u8], &'a [u8])]) -> Self {
        Self {
            responses,
            step: 0.into(),
        }
    }
}

impl<'a> Backend for MockBackend<'a> {
    type Error = Infallible;

    async fn exchange_raw(&self, output: &mut [u8], input: &[u8]) -> Result<usize, Self::Error> {
        let (expected_input, response) = {
            let n = self.step.fetch_add(1, Ordering::SeqCst) as usize;
            let responses = &self.responses[n..];
            responses[0]
        };
        assert_eq!(expected_input, input);
        let n = response.len();
        output[..n].copy_from_slice(response);
        Ok(n)
    }
}

#[allow(unused_macros)]
macro_rules! mock_backend {
    ( $( ( $request:expr, $response:expr ) ),* ) => {
        $crate::io::MockBackend::new(&[
            $(
                (&hex_literal::hex!($request), &hex_literal::hex!($response))
            ),*
        ])
    };
}
pub(crate) use mock_backend;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_backend() {
        let mb = MockBackend::new(&[(&[0xAF], b"\x00Hello, World!")]);
        let mut out = [0; 0xff];
        let n = mb.exchange_raw(&mut out, &[0xAF]).await.unwrap();
        assert_eq!(b"Hello, World!", &out[1..n]);
    }
}

// vim: foldmethod=marker
