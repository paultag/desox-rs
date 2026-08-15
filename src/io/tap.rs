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
use crate::std::vec::Vec;
use tokio::sync::Mutex;

/// The [TapBackend] wraps another [Backend] and stores the messages for
/// replay later.
#[derive(Debug)]
pub struct TapBackend<IoBackendT>
where
    IoBackendT: Backend,
{
    backend: IoBackendT,
    messages: Mutex<Vec<(Vec<u8>, Vec<u8>)>>,
}

impl<IoBackendT> TapBackend<IoBackendT>
where
    IoBackendT: Backend,
{
    /// Create a new [TapBackend] wrapping the provided (real?) backend.
    pub fn new(backend: IoBackendT) -> Self {
        Self {
            backend,
            messages: Mutex::new(Vec::new()),
        }
    }

    /// Consume the [TapBackend] and return the logged messages.
    pub fn into_inner(self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.messages.into_inner()
    }
}

impl<IoBackendT> Backend for TapBackend<IoBackendT>
where
    IoBackendT: Backend,
{
    type Error = IoBackendT::Error;

    async fn exchange_raw(&self, output: &mut [u8], input: &[u8]) -> Result<usize, Self::Error> {
        let n = self.backend.exchange_raw(output, input).await?;
        {
            let mut messages = self.messages.lock().await;
            messages.push((input.to_vec(), output[..n].to_vec()));
        }
        Ok(n)
    }
}

// vim: foldmethod=marker
