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

use crate::{Error, StatusCode, io, std::future::Future};

/// Depending on the state that a card is in, the bytes exchanged will look
/// a bit different.
///
/// - When unauthenticated, everything is 'PLAIN' in and 'PLAIN' out. Calling
///   this trait's methods while Unauthenticated will result in 'PLAIN' calls.
///
/// - However, when Authenticated, the default is 'PLAIN' in and 'CMAC' out.
///   We need to update the hash on both sides, or we will fall out of sync.
///
/// This trait will pick the right way to send a message when it's assumed
/// to be a default communication pattern.
pub trait CardIoDefault<IoBackendT>
where
    IoBackendT: io::Backend,
{
    /// Communicate with a card using the default transport mechanism
    /// (plain, cmac).
    ///
    /// Functions with better information than this trait
    /// may opt to just directly communicate with the [io::Backend]
    /// directly, as long as the state (e.g., cmac hashes) continue to be
    /// updated correctly.
    fn default_exchange<'a>(
        &mut self,
        output: &'a mut [u8],
        input: &[u8],
    ) -> impl Future<Output = Result<(StatusCode, &'a [u8]), Error<IoBackendT::Error>>> {
        self.default_exchange_multi(output, input, &[])
    }

    /// Communicate with a card using the default transport mechanism
    /// (plain, cmac).
    ///
    /// Functions with better information than this trait
    /// may opt to just directly communicate with the [io::Backend]
    /// directly.
    ///
    /// This will exchange data by sending the `header`, followed by each
    /// `data` entry, in order.
    fn default_exchange_multi<'a>(
        &mut self,
        output: &'a mut [u8],
        header: &[u8],
        data: &[&[u8]],
    ) -> impl Future<Output = Result<(StatusCode, &'a [u8]), Error<IoBackendT::Error>>>;
}

// vim: foldmethod=marker
