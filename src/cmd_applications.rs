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

use super::{
    Authenticated, AuthenticationState, Card, CardIoDefault, Unauthenticated, command_de_minimis,
    command_encrypted_request_de_minimis,
};
use crate::{ApplicationId, Error, Instruction, Key, KeyCount, Permissions, StatusCode, io};

impl<'card, IoBackendT, AuthenticationStateT> Card<'card, IoBackendT, AuthenticationStateT>
where
    AuthenticationStateT: AuthenticationState,
    IoBackendT: io::Backend,
    Self: CardIoDefault<IoBackendT>,
{
    /// Get information about the hardware/software version.
    pub async fn list_applications<'a>(
        &mut self,
        out: &'a mut [u8],
    ) -> Result<&'a [ApplicationId], Error<IoBackendT::Error>> {
        let (status_code, response) = self
            .default_exchange(out, &[Instruction::GetApplicationIdList as u8])
            .await?;

        #[cfg(feature = "tracing")]
        tracing::debug!(
            method = "list_applications",
            status_code = format!("{:?}", status_code)
        );

        if status_code != StatusCode::Ack {
            return Err(Error::BadStatusCode(status_code));
        }

        let (application_ids, &[]) = response.as_chunks::<3>() else {
            return Err(Error::BadSize);
        };

        Ok(application_ids)
    }

    /// Return the currently selected application
    pub fn get_current_application(&self) -> ApplicationId {
        self.application_id
    }

    /// Select an application.
    ///
    /// This consumes `self` and returns a new (unauthenticated) card.
    pub async fn select_application(
        self,
        application_id: ApplicationId,
    ) -> Result<Card<'card, IoBackendT, Unauthenticated>, Error<IoBackendT::Error>> {
        let mut card = self.to_unauthenticated();

        let (status_code, response) = command_de_minimis!((&mut card), {
            instruction: Instruction = Instruction::SelectApplication,
            application_id: ApplicationId = application_id
        }, 4, []);

        #[cfg(feature = "tracing")]
        tracing::debug!(
            method = "select_application",
            application_id = hex::encode(application_id),
            status_code = format!("{:?}", status_code)
        );

        if !response.is_empty() {
            return Err(Error::BadSize);
        };

        if status_code != StatusCode::Ack {
            return Err(Error::BadStatusCode(status_code));
        }

        card.application_id = application_id;
        Ok(card)
    }

    /// Create an Application
    pub async fn create_application(
        &mut self,
        application_id: ApplicationId,
        key_settings: Permissions,
        key_number: KeyCount,
    ) -> Result<(), Error<IoBackendT::Error>> {
        let (status_code, response) = command_de_minimis!(self, {
            instruction: Instruction = Instruction::CreateApplication,
            application_id: ApplicationId = application_id,
            key_settings: u8 = key_settings.as_u8()?,
            key_number: u8 = key_number.as_u8()?
        }, 6, []);

        #[cfg(feature = "tracing")]
        tracing::debug!(
            method = "create_application",
            application_id = hex::encode(application_id),
            key_settings = format!("{:?}", key_settings),
            key_number = format!("{:?}", key_number),
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

    /// Delete an application
    pub async fn delete_application(
        &mut self,
        application_id: ApplicationId,
    ) -> Result<(), Error<IoBackendT::Error>> {
        let (status_code, response) = command_de_minimis!(self, {
            instruction: Instruction = Instruction::DeleteApplication,
            application_id: ApplicationId = application_id
        }, 4, []);

        #[cfg(feature = "tracing")]
        tracing::debug!(
            method = "delete_application",
            application_id = hex::encode(application_id),
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

impl<'card, IoBackendT> Card<'card, IoBackendT, Authenticated>
where
    IoBackendT: io::Backend,
{
    /// This will change the default key (0x00) that is set after we
    /// create an application.
    pub async fn change_default_application_key(
        &mut self,
        key: Key,
        key_version: u8,
    ) -> Result<(), Error<IoBackendT::Error>> {
        let mut default_key = [0; 24];
        match key {
            Key::Aes(key) => default_key[..16].copy_from_slice(&key),
            Key::Des(key) => default_key[..8].copy_from_slice(&key),
        }

        let (status_code, response) = command_encrypted_request_de_minimis!(self, {
            instruction: Instruction = Instruction::SetConfiguration,
            configuration_key: u8 = 0x01
        }, 2, [&default_key, &[key_version]]);

        #[cfg(feature = "tracing")]
        tracing::debug!(
            method = "change_default_application_key",
            default_key = hex::encode(default_key),
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
