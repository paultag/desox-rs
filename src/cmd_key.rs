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
    Authenticated, AuthenticationState, Card, CardIoDefault, Error, Instruction, KeyCount, KeyId,
    Permissions, Session, StatusCode, command_header, crc32, io,
};

impl<IoBackendT, AuthenticationStateT> Card<IoBackendT, AuthenticationStateT>
where
    AuthenticationStateT: AuthenticationState,
    IoBackendT: io::Backend,
    Self: CardIoDefault<IoBackendT>,
{
    /// Get information about the key settings. This returns the key settings
    /// bits (0th element of the returned tuple), as well as the number
    /// of keys present (1st element of the returned tuple).
    pub async fn get_key_settings(
        &mut self,
    ) -> Result<(Permissions, KeyCount), Error<IoBackendT::Error>> {
        let (status_code, &[key_settings, num_keys]) = self
            .default_exchange_de_minimis(&[Instruction::GetKeySettings as u8])
            .await?
        else {
            return Err(Error::BadSize);
        };

        #[cfg(feature = "tracing")]
        tracing::debug!(
            method = "get_key_settings",
            status_code = format!("{:?}", status_code)
        );

        if status_code != StatusCode::Ack {
            return Err(Error::BadStatusCode(status_code));
        }

        Ok((
            Permissions::from_u8(key_settings),
            KeyCount::from_u8(num_keys)?,
        ))
    }

    /// Return the version of a Key by ID
    pub async fn get_key_version(&mut self, key_id: KeyId) -> Result<u8, Error<IoBackendT::Error>> {
        let (status_code, &[key_version]) = self
            .default_exchange_de_minimis(&[Instruction::GetKeyVersion as u8, key_id])
            .await?
        else {
            return Err(Error::BadSize);
        };

        #[cfg(feature = "tracing")]
        tracing::debug!(
            method = "get_key_version",
            key_id = key_id,
            status_code = format!("{:?}", status_code)
        );

        if status_code != StatusCode::Ack {
            return Err(Error::BadStatusCode(status_code));
        }

        Ok(key_version)
    }
}

impl<IoBackendT> Card<IoBackendT, Authenticated>
where
    IoBackendT: io::Backend,
    Self: CardIoDefault<IoBackendT>,
{
    /// Set the key settings for an application. This can be used to lock
    /// the door behind you after changing keys, etc.
    pub async fn set_key_settings(
        &mut self,
        permissions: Permissions,
    ) -> Result<(), Error<IoBackendT::Error>> {
        let header: [u8; 1] = command_header!({
            instruction: Instruction = Instruction::ChangeKeySettings
        }, 1);

        let permissions: &[u8] = &[permissions.as_u8()?][..];
        let crc = crc32(&header, &[permissions]).to_le_bytes();

        let (status_code, response) = match &mut self.authentication.session {
            Session::Aes { keying, .. } => {
                io::encrypted_out_cmac_in(
                    &self.card,
                    keying,
                    &mut self.buf,
                    &header,
                    &[permissions, &crc],
                )
                .await?
            }
            Session::Des { keying, .. } => {
                io::encrypted_out_cmac_in(
                    &self.card,
                    keying,
                    &mut self.buf,
                    &header,
                    &[permissions, &crc],
                )
                .await?
            }
        };

        #[cfg(feature = "tracing")]
        tracing::debug!(
            method = "set_key_settings",
            permissions = format!("{:?}", permissions),
            crc = hex::encode(crc),
            status_code = format!("{:?}", status_code)
        );

        if status_code != StatusCode::Ack {
            return Err(Error::BadStatusCode(status_code));
        }

        if !response.is_empty() {
            return Err(Error::BadSize);
        };

        Ok(())
    }
}

// vim: foldmethod=marker
