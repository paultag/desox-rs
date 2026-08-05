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

use super::{AuthenticationState, Card, CardIoDefault};
use crate::{Error, StatusCode, io};

/// Unauthenticated session. Everything is plaintext.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Unauthenticated;

impl AuthenticationState for Unauthenticated {}

impl<'card, IoBackendT> CardIoDefault<IoBackendT> for Card<'card, IoBackendT, Unauthenticated>
where
    IoBackendT: io::Backend,
{
    async fn default_exchange_multi<'a>(
        &mut self,
        output: &'a mut [u8],
        header: &[u8],
        data: &[&[u8]],
    ) -> Result<(StatusCode, &'a [u8]), Error<IoBackendT::Error>> {
        io::plain_multi(&self.card, output, header, data).await
    }
}

impl<'card, IoBackendT> Card<'card, IoBackendT, Unauthenticated>
where
    IoBackendT: io::Backend,
{
    /// Create a new [Card].
    pub fn new(card: &'card IoBackendT) -> Self {
        Self {
            card,
            buf: [0; 0xff],
            authentication: Unauthenticated,
        }
    }
}

// vim: foldmethod=marker
