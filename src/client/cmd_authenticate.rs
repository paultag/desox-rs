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
    crc32,
    crypto::xor,
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
            application_id,
            authentication: _,
        } = self;

        Ok(Card {
            card,
            buf,
            application_id,
            authentication: Authenticated { session },
        })
    }

    /// Authenticate (in the same way as we would with [Self::authenticate],
    /// except hardcode the RND A half of the session key. This is almost
    /// always a bad idea, except for testing (which is what I use it for).
    /// You should basically never use this, and this may even go away in a
    /// future release (or hide it behind a feature).
    pub async fn authenticate_with_rnd_a(
        self,
        key_id: KeyId,
        key: Key,
        rnd_a: Key,
    ) -> Result<Card<'card, IoBackendT, Authenticated>, Error<IoBackendT::Error>> {
        let session: Session = match (rnd_a, key) {
            (Key::Aes(rnd_a), Key::Aes(key)) => {
                let session_key = AuthenticateExt::<16, aes::Aes128>::authenticate_with_rnd_a(
                    &self.card,
                    key_id,
                    key,
                    Some(rnd_a),
                )
                .await?;
                Session::Aes {
                    key_id,
                    keying: KeyingState::<16, aes::Aes128>::new(session_key),
                }
            }
            (Key::Des(rnd_a), Key::Des(key)) => {
                let session_key = AuthenticateExt::<8, des::Des>::authenticate_with_rnd_a(
                    &self.card,
                    key_id,
                    key,
                    Some(rnd_a),
                )
                .await?;
                Session::Des {
                    key_id,
                    keying: KeyingState::<8, des::Des>::new(session_key),
                }
            }
            _ => {
                panic!("rnd_a and key must be of the same type");
            }
        };

        let Self {
            card,
            buf,
            application_id,
            authentication: _,
        } = self;

        Ok(Card {
            card,
            buf,
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
        mut self,
        new_key: Key,
        new_key_version: u8,
    ) -> Result<Card<'card, IoBackendT, Unauthenticated>, Error<IoBackendT::Error>> {
        let mut key_id = self.authentication.session.get_key_id();

        let Self {
            card,
            buf,
            application_id,
            mut authentication,
        } = self;

        if application_id == [0; 3] {
            // If we're in the default '00 00 00' application, we need to
            // change the key id's high bits to indicate the key type. when
            // making an application, we can provide the [crate::KeyCount]
            // to specify algorithm, but no such luck here. As such, we can
            // set the high bit as required.

            key_id |= match new_key {
                Key::Aes(_) => 0x80,
                Key::Des(_) => 0x00,
            };
        } else {
            // Otherwise, we're in an actual application -- something where
            // we set the key algorithm when we created the application itself.
            //
            // As such, unlike the PICC default application (0x000000), we
            // can't set the high bits of the key_id to indicate an algorithm
            // change. This means that we need to check (and error) if the
            // session and algorithm do not match when we're in a non-default
            // application.
            match (&authentication.session, new_key) {
                (Session::Aes { .. }, Key::Aes(_)) => {}
                (Session::Des { .. }, Key::Des(_)) => {}
                _ => {
                    return Err(Error::BadAlgorithm);
                }
            }
        }

        let header: [u8; 2] = command_header!({
            instruction: Instruction = Instruction::ChangeKey,
            key_id: KeyId = key_id
        }, 2);

        let data: &[&[u8]] = match &new_key {
            Key::Aes(key) => &[key, &[new_key_version]],
            Key::Des(key) => &[key, key],
        };
        let crc = crc32(&header, data).to_le_bytes();
        let data: &[&[u8]] = match &new_key {
            Key::Aes(key) => &[key, &[new_key_version], &crc],
            Key::Des(key) => &[key, key, &crc],
        };

        // We can't use command_encrypted_request here because the response
        // isn't CMAC; it's plain (since the operation itself is what will
        // tear down the session). As a result, we have to explicitly call
        // encrypted_out__in so we don't try to validate cmac, we are
        // dropping the session anyway at function return.

        let (status_code, response) = match &mut authentication.session {
            Session::Aes { keying, .. } => {
                io::encrypted_out_plain_in(&card, keying, &mut self.buf, &header, data).await?
            }
            Session::Des { keying, .. } => {
                io::encrypted_out_plain_in(&card, keying, &mut self.buf, &header, data).await?
            }
        };

        #[cfg(feature = "tracing")]
        tracing::debug!(
            method = "change_current_key",
            key_id = key_id,
            new_key = format!("{:?}", new_key),
            new_key_version = new_key_version,
            status_code = format!("{:?}", status_code)
        );

        if !response.is_empty() {
            return Err(Error::BadSize);
        };

        if status_code != StatusCode::Ack {
            return Err(Error::BadStatusCode(status_code));
        }

        Ok(Card {
            card,
            buf,
            application_id,
            authentication: Unauthenticated,
        })
    }

    /// Change the currently authenticated key ID to something new (`new_key`).
    /// This requires that we prove knowledge of the current key.
    pub async fn change_key(
        &mut self,
        key_id: KeyId,
        current_key: Key,
        new_key: Key,
        new_key_version: u8,
    ) -> Result<(), Error<IoBackendT::Error>> {
        if self.application_id == [0; 3] {
            // There's only one root application key, so we can only
            // run this inside an application.
            return Err(Error::NoSelectedApplication);
        }

        let header: [u8; 2] = command_header!({
            instruction: Instruction = Instruction::ChangeKey,
            key_id: KeyId = key_id
        }, 2);

        let mut xor_key = new_key;
        let new_key_crc = match (&mut xor_key, &current_key) {
            (Key::Aes(xor_key), Key::Aes(current_key)) => {
                let crc = crc32(xor_key, &[]);
                xor(xor_key, current_key);
                crc
            }
            (Key::Des(xor_key), Key::Des(current_key)) => {
                let crc = crc32(xor_key, &[]);
                xor(xor_key, current_key);
                crc
            }
            _ => {
                return Err(Error::BadAlgorithm);
            }
        }
        .to_le_bytes();

        let (status_code, response) = match (&mut self.authentication.session, xor_key) {
            (Session::Aes { keying, .. }, Key::Aes(key)) => {
                let crc = crc32(&header, &[&key, &[new_key_version]]).to_le_bytes();
                io::encrypted_out_cmac_in(
                    &self.card,
                    keying,
                    &mut self.buf,
                    &header,
                    &[&key, &[new_key_version], &crc, &new_key_crc],
                )
                .await?
            }
            (Session::Des { keying, .. }, Key::Des(key)) => {
                let crc = crc32(&header, &[&key]).to_le_bytes();
                io::encrypted_out_cmac_in(
                    &self.card,
                    keying,
                    &mut self.buf,
                    &header,
                    &[&key, &crc, &new_key_crc],
                )
                .await?
            }
            _ => {
                return Err(Error::BadAlgorithm);
            }
        };

        #[cfg(feature = "tracing")]
        tracing::debug!(
            method = "change_key",
            status_code = format!("{:?}", status_code)
        );

        if !response.is_empty() {
            return Err(Error::BadSize);
        };

        if status_code != StatusCode::Ack {
            return Err(Error::BadStatusCode(status_code));
        }

        Ok(())
    }
}

// vim: foldmethod=marker
