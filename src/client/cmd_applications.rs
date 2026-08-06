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

use super::{Authenticated, AuthenticationState, Card, CardIoDefault, Unauthenticated, command};
use crate::{ApplicationId, Error, Instruction, KeyCount, KeySettings, StatusCode, io};

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

        if status_code != StatusCode::Ack {
            return Err(Error::BadStatusCode);
        }

        let (application_ids, &[]) = response.as_chunks::<3>() else {
            return Err(Error::BadSize);
        };

        Ok(application_ids)
    }

    /// Return the currently selected application
    pub async fn get_current_application(&self) -> ApplicationId {
        self.application_id
    }
}

impl<'card, IoBackendT> Card<'card, IoBackendT, Authenticated>
where
    IoBackendT: io::Backend,
{
    /// Select an application.
    ///
    /// This consumes `self` and returns a new (unauthenticated) card.
    pub async fn select_application<'a>(
        self,
        out: &'a mut [u8],
        application_id: ApplicationId,
    ) -> Result<Card<'card, IoBackendT, Unauthenticated>, Error<IoBackendT::Error>> {
        // TODO: check if we're switching to the same application we're
        // currently in and raise an error, since otherwise we'll transition
        // to unauthenticated.
        let card = self.to_unauthenticated();
        card.select_application(out, application_id).await
    }

    /// Create an Application
    pub async fn create_application(
        &mut self,
        out: &mut [u8],
        application_id: ApplicationId,
        key_settings: KeySettings,
        key_number: KeyCount,
    ) -> Result<(), Error<IoBackendT::Error>> {
        let (status_code, response) = command!(self, out, {
            instruction: Instruction = Instruction::CreateApplication,
            application_id: ApplicationId = application_id,
            key_settings: u8 = key_settings.as_u8()?,
            key_number: u8 = key_number.as_u8()?
        }, []);

        if !response.is_empty() {
            return Err(Error::BadSize);
        };

        if status_code != StatusCode::Ack {
            return Err(Error::BadStatusCode);
        }

        Ok(())
    }

    /// Delete an application
    pub async fn delete_application(
        &mut self,
        out: &mut [u8],
        application_id: ApplicationId,
    ) -> Result<(), Error<IoBackendT::Error>> {
        let (status_code, response) = command!(self, out, {
            instruction: Instruction = Instruction::DeleteApplication,
            application_id: ApplicationId = application_id
        }, []);

        if !response.is_empty() {
            return Err(Error::BadSize);
        };

        if status_code != StatusCode::Ack {
            return Err(Error::BadStatusCode);
        }

        Ok(())
    }
}

impl<'card, IoBackendT> Card<'card, IoBackendT, Unauthenticated>
where
    IoBackendT: io::Backend,
{
    /// Select an application.
    pub async fn select_application(
        mut self,
        out: &mut [u8],
        application_id: ApplicationId,
    ) -> Result<Self, Error<IoBackendT::Error>> {
        let (status_code, response) = command!((&mut self), out, {
            instruction: Instruction = Instruction::SelectApplication,
            application_id: ApplicationId = application_id
        }, []);

        if !response.is_empty() {
            return Err(Error::BadSize);
        };

        if status_code != StatusCode::Ack {
            return Err(Error::BadStatusCode);
        }

        self.application_id = application_id;

        Ok(self)
    }
}

// vim: foldmethod=marker
