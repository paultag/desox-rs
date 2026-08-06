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
    Error, Instruction, Key, KeyId, StatusCode, Unauthenticated,
    client::{
        AuthenticateExt, Authenticated, AuthenticationState, Card, KeyingState, Session,
        command_header,
    },
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
            application_id,
            authentication: _,
        } = self;

        Ok(Card {
            card,
            application_id,
            authentication: Authenticated { session },
        })
    }
}

impl<'card, IoBackendT> Card<'card, IoBackendT, Authenticated>
where
    IoBackendT: io::Backend,
{
    /// Change the currently authenticated key ID to something new (`new_key`).
    pub async fn change_current_key(
        self,
        out: &mut [u8],
        new_key: Key,
        new_key_version: u8,
    ) -> Result<Card<'card, IoBackendT, Unauthenticated>, Error<IoBackendT::Error>> {
        let header: &[u8] = command_header!({
            instruction: Instruction = Instruction::ChangeKey,
            key_id: KeyId = self.authentication.session.get_key_id()
        });

        let Self {
            mut authentication,
            application_id,
            card,
        } = self;

        // We can't use command_encrypted_request here because the response
        // isn't CMAC; it's plain (since the operation itself is what will
        // tear down the session). As a result, we have to explicitly call
        // encrypted_out_plain_in so we don't try to validate cmac, we are
        // dropping the session anyway at function return.

        let (status_code, response) = match (&mut authentication.session, new_key) {
            (Session::Aes { keying, .. }, Key::Aes(key)) => {
                io::encrypted_out_plain_in(&card, keying, out, &header, &[&key, &[new_key_version]])
                    .await?
            }
            (Session::Des { keying, .. }, Key::Des(key)) => {
                io::encrypted_out_plain_in(&card, keying, out, &header, &[&key]).await?
            }
            _ => {
                return Err(Error::BadAlgorithm);
            }
        };

        if !response.is_empty() {
            return Err(Error::BadSize);
        };

        if status_code != StatusCode::Ack {
            return Err(Error::BadStatusCode);
        }

        Ok(Card {
            authentication: Unauthenticated,
            application_id,
            card,
        })
    }
}

// vim: foldmethod=marker
