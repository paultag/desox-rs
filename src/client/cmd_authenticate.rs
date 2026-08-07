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
        let mut key_id = self.authentication.session.get_key_id();

        if self.application_id == [0; 3] {
            // If we're in the default '00 00 00' application, we need to
            // change the key id's high bits to indicate the key type. when
            // making an application, we can provide the [crate::KeyCount]
            // to specify algorithm, but no such luck here. As such, we can
            // set the high bit as required.

            key_id |= match new_key {
                Key::Aes(_) => 0x80,
                Key::Des(_) => 0x00,
            };
        }

        let header: [u8; 2] = command_header!({
            instruction: Instruction = Instruction::ChangeKey,
            key_id: KeyId = key_id
        }, 2);

        let Self {
            mut authentication,
            application_id,
            card,
        } = self;

        // We can't use command_encrypted_request here because the response
        // isn't CMAC; it's plain (since the operation itself is what will
        // tear down the session). As a result, we have to explicitly call
        // encrypted_out__in so we don't try to validate cmac, we are
        // dropping the session anyway at function return.

        let (status_code, response) = match (&mut authentication.session, new_key) {
            (Session::Aes { keying, .. }, Key::Aes(key)) => {
                // Changing AES key to a new AES key
                //
                // [CHPW] [KEY ID] [   KEY   ] [ VER ] [ CRC ]
                //
                let crc = crc32(&header, &[&key, &[new_key_version]]).to_le_bytes();
                io::encrypted_out_plain_in(
                    &card,
                    keying,
                    out,
                    &header,
                    &[&key, &[new_key_version], &crc],
                )
                .await?
            }
            (Session::Aes { keying, .. }, Key::Des(key)) => {
                // Changing AES key to a new DES key (WTF). Here we need to
                // pad the key out to 16 bytes, and the version/crc is assumed
                // to start there.
                //
                // [CHPW] [KEY ID] [ KEY ] [ PAD TO 16 ] [ CRC ]
                //
                let crc = crc32(&header, &[&key, &[0; 8]]).to_le_bytes();
                io::encrypted_out_plain_in(&card, keying, out, &header, &[&key, &[0; 8], &crc])
                    .await?
            }
            (Session::Des { keying, .. }, Key::Aes(key)) => {
                // Changing DES key to a new AES key (nice)
                //
                // [CHPW] [KEY ID] [   KEY   ] [ VER ] [ CRC ]
                //
                let crc = crc32(&header, &[&key, &[new_key_version]]).to_le_bytes();
                io::encrypted_out_plain_in(
                    &card,
                    keying,
                    out,
                    &header,
                    &[&key, &[new_key_version], &crc],
                )
                .await?
            }
            (Session::Des { keying, .. }, Key::Des(key)) => {
                // Changing DES key to a new DES key (fine whatever)
                //
                // [CHPW] [KEY ID] [   KEY   ] [ CRC ]
                //
                let crc = crc32(&header, &[&key]).to_le_bytes();
                io::encrypted_out_plain_in(&card, keying, out, &header, &[&key, &crc]).await?
            }
        };

        if !response.is_empty() {
            return Err(Error::BadSize);
        };

        if status_code != StatusCode::Ack {
            return Err(Error::BadStatusCode(status_code));
        }

        Ok(Card {
            authentication: Unauthenticated,
            application_id,
            card,
        })
    }

    /// Change the currently authenticated key ID to something new (`new_key`).
    /// This requires that we prove knowledge of the current key.
    pub async fn change_key(
        &mut self,
        out: &mut [u8],
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
                    out,
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
                    out,
                    &header,
                    &[&key, &crc, &new_key_crc],
                )
                .await?
            }
            _ => {
                return Err(Error::BadAlgorithm);
            }
        };

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
