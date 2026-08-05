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
    Error, Key, KeyId,
    client::{AuthenticateExt, Authenticated, AuthenticationState, Card, KeyingState, Session},
    io,
};

impl<'card, IoBackendT, AuthenticationStateT> Card<'card, IoBackendT, AuthenticationStateT>
where
    AuthenticationStateT: AuthenticationState,
    IoBackendT: io::Backend,
    IoBackendT: AuthenticateExt<8, des::Des>,
    IoBackendT: AuthenticateExt<16, aes::Aes128>,
{
    /// Authenticate to the selected Application (or the PICC, if no
    /// application is selected, using the key stored in the card under the
    /// provided [KeyId] (`key_id`) using the provided [Key] (`key`) to the
    /// card in order to establish a shared session key state to encrypt or
    /// sign messages.
    pub async fn authenticate(
        self,
        key_id: KeyId,
        key: Key,
    ) -> Result<Card<'card, IoBackendT, Authenticated>, Error<IoBackendT::Error>> {
        let session: Session = match key {
            Key::Aes(key) => {
                let session_key =
                    AuthenticateExt::<16, aes::Aes128>::authenticate(&self.card, key_id, key)
                        .await?;
                Session::Aes {
                    key_id,
                    keying: KeyingState::<16, aes::Aes128>::new(session_key),
                }
            }
            Key::Des(key) => {
                let session_key =
                    AuthenticateExt::<8, des::Des>::authenticate(&self.card, key_id, key).await?;
                Session::Des {
                    key_id,
                    keying: KeyingState::<8, des::Des>::new(session_key),
                }
            }
        };

        let Self {
            card,
            buf,
            authentication: _,
        } = self;

        Ok(Card {
            card,
            buf,
            authentication: Authenticated { session },
        })
    }
}

// vim: foldmethod=marker
