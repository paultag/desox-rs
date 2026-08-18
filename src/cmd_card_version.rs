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

use crate::{
    AuthenticationState, Card, CardIoDefault, Error, Instruction, StatusCode, VersionInfo, io,
};

impl<'card, IoBackendT, AuthenticationStateT> Card<'card, IoBackendT, AuthenticationStateT>
where
    AuthenticationStateT: AuthenticationState,
    IoBackendT: io::Backend,
    Self: CardIoDefault<IoBackendT>,
{
    /// Get information about the hardware/software version.
    pub async fn get_version_info(&mut self) -> Result<VersionInfo, Error<IoBackendT::Error>> {
        let mut out = [0; 0xff];
        let (status_code, response) = self
            .default_exchange(&mut out, &[Instruction::GetVersionInfo as u8])
            .await?;

        #[cfg(feature = "tracing")]
        tracing::debug!(
            method = "get_version_info",
            status_code = format!("{:?}", status_code)
        );

        if status_code != StatusCode::Ack {
            return Err(Error::BadStatusCode(status_code));
        }

        let response: &[u8; 28] = response.try_into().map_err(|_| Error::BadSize)?;
        Ok(VersionInfo::parse(response))
    }
}

// vim: foldmethod=marker
