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

use super::{AuthenticationState, Card, CardIoDefault, Unauthenticated};
use crate::{Error, KeyId, Session, StatusCode, io};

/// Authenticated Session
pub struct Authenticated {
    pub(crate) session: Session,
}

impl Authenticated {
    /// Return a handle to the underlying [Session].
    pub fn session(&self) -> &Session {
        &self.session
    }

    /// Return a handle to the underlying [Session] (mutable).
    pub fn session_mut(&mut self) -> &mut Session {
        &mut self.session
    }
}

impl AuthenticationState for Authenticated {}

impl<IoBackendT> CardIoDefault<IoBackendT> for Card<IoBackendT, Authenticated>
where
    IoBackendT: io::Backend,
{
    async fn default_exchange_multi<'a>(
        &mut self,
        output: &'a mut [u8],
        header: &[u8],
        data: &[&[u8]],
    ) -> Result<(StatusCode, &'a [u8]), Error<IoBackendT::Error>> {
        Ok(match &mut self.authentication.session {
            Session::Aes { keying, .. } => {
                io::plain_out_cmac_in(&mut self.card, keying, output, header, data).await?
            }
            Session::Des { keying, .. } => {
                io::plain_out_cmac_in(&mut self.card, keying, output, header, data).await?
            }
        })
    }

    async fn default_exchange_multi_de_minimis<'a>(
        &'a mut self,
        header: &[u8],
        data: &[&[u8]],
    ) -> Result<(StatusCode, &'a [u8]), Error<IoBackendT::Error>> {
        Ok(match &mut self.authentication.session {
            Session::Aes { keying, .. } => {
                io::plain_out_cmac_in(&mut self.card, keying, &mut self.buf, header, data).await?
            }
            Session::Des { keying, .. } => {
                io::plain_out_cmac_in(&mut self.card, keying, &mut self.buf, header, data).await?
            }
        })
    }
}

impl<IoBackendT> Card<IoBackendT, Authenticated>
where
    IoBackendT: io::Backend,
{
    /// Return the currently authenticated key id
    pub fn get_current_key_id(&self) -> KeyId {
        self.authentication.session.get_key_id()
    }
}

impl<IoBackendT, AuthenticationStateT> Card<IoBackendT, AuthenticationStateT>
where
    AuthenticationStateT: AuthenticationState,
    IoBackendT: io::Backend,
{
    /// Drop Authentication. This doesn't actually change anything on the
    /// card state -- this is only useful if you (the user) know you did
    /// something that caused you to be "logged out" that the type system
    /// didn't account for.
    pub fn to_unauthenticated(self) -> Card<IoBackendT, Unauthenticated> {
        let Self {
            card,
            buf,
            application_id,
            authentication: _,
        } = self;

        Card::<IoBackendT, Unauthenticated> {
            card,
            buf,
            application_id,
            authentication: Unauthenticated,
        }
    }
}

// vim: foldmethod=marker
