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
    AuthenticationState, Card, CardIoDefault, Error, FileCommunication, FileId, FilePermissions,
    FileSettings, FileType, Instruction, StatusCode, U24, command, command_de_minimis, io,
};

impl<'card, IoBackendT, AuthenticationStateT> Card<'card, IoBackendT, AuthenticationStateT>
where
    AuthenticationStateT: AuthenticationState,
    IoBackendT: io::Backend,
    Self: CardIoDefault<IoBackendT>,
{
    /// Read from a file
    pub async fn list_files<'a>(
        &mut self,
        out: &'a mut [u8],
    ) -> Result<&'a [FileId], Error<IoBackendT::Error>> {
        let (status_code, response) = command!(self, out, {
            instruction: Instruction = Instruction::ListFiles
        }, 1, []);

        #[cfg(feature = "tracing")]
        tracing::debug!(
            method = "list_files",
            status_code = format!("{:?}", status_code)
        );

        if status_code != StatusCode::Ack {
            return Err(Error::BadStatusCode(status_code));
        }

        Ok(response)
    }
    /// Read from a file
    pub async fn get_file_settings(
        &mut self,
        file_id: FileId,
    ) -> Result<FileSettings, Error<IoBackendT::Error>> {
        let (status_code, response) = command_de_minimis!(self, {
            instruction: Instruction = Instruction::GetFileSettings,
            file_id: u8 = file_id
        }, 2, []);

        #[cfg(feature = "tracing")]
        tracing::debug!(
            method = "get_file_settings",
            file_id = file_id,
            status_code = format!("{:?}", status_code)
        );

        if status_code != StatusCode::Ack {
            return Err(Error::BadStatusCode(status_code));
        }

        if response.len() != 7 {
            return Err(Error::BadSize);
        };

        let type_ = FileType::from_u8(response[0])?;
        let communication = FileCommunication::from_u8(response[1])?;
        let permissions = FilePermissions::from_bytes([response[2], response[3]])?;

        Ok(match type_ {
            FileType::Data => {
                let size = U24::from_le_bytes([response[4], response[5], response[6]]);
                FileSettings::Data {
                    communication,
                    permissions,
                    size,
                }
            }
            FileType::Backup => {
                let size = U24::from_le_bytes([response[4], response[5], response[6]]);
                FileSettings::Backup {
                    communication,
                    permissions,
                    size,
                }
            }
        })
    }

    /// Create a file within the currently open application.
    pub async fn create_file(
        &mut self,
        file_id: FileId,
        settings: FileSettings,
    ) -> Result<(), Error<IoBackendT::Error>> {
        let FileSettings::Data {
            communication,
            permissions,
            size,
        } = settings
        else {
            unimplemented!();
        };

        let (status_code, response) = command_de_minimis!(self, {
            instruction: Instruction = Instruction::CreateDataFile,
            file_id: u8 = file_id,
            communication: u8 = communication.as_u8(),
            permissions: [u8; 2] = permissions.as_bytes()?,
            size: [u8; 3] = U24::to_le_bytes(size)
        }, 8, []);

        #[cfg(feature = "tracing")]
        tracing::debug!(
            method = "create_file",
            file_id = file_id,
            communication = format!("{:?}", communication),
            permissions = format!("{:?}", permissions),
            size = size,
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

    /// Delete a file
    pub async fn delete_file(&mut self, file_id: FileId) -> Result<(), Error<IoBackendT::Error>> {
        let (status_code, response) = command_de_minimis!(self, {
            instruction: Instruction = Instruction::DeleteFile,
            file_id: FileId = file_id
        }, 2, []);

        #[cfg(feature = "tracing")]
        tracing::debug!(
            method = "delete_file",
            file_id = file_id,
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

    /// Get the amount of free memory remaining on the card
    pub async fn get_free_memory(&mut self) -> Result<u32, Error<IoBackendT::Error>> {
        let (status_code, &[s1, s2, s3]) = self
            .default_exchange_de_minimis(&[Instruction::GetFreeMemory as u8])
            .await?
        else {
            return Err(Error::BadSize);
        };

        #[cfg(feature = "tracing")]
        tracing::debug!(
            method = "get_free_memory",
            status_code = format!("{:?}", status_code)
        );

        if status_code != StatusCode::Ack {
            return Err(Error::BadStatusCode(status_code));
        }

        let size = U24::from_le_bytes([s1, s2, s3]);
        Ok(size)
    }
}

#[cfg(test)]
mod tests {
    use crate::{Card, io::MockBackend};

    #[tokio::test]
    async fn test_free_memory() {
        let mb = MockBackend::new(&[(&[0x6e], &[0x00, 0x00, 0x04, 0x00])]);
        let mut card = Card::new(&mb);
        assert_eq!(1024, card.get_free_memory().await.unwrap());
    }

    #[tokio::test]
    async fn test_free_memory_sc() {
        let mb = MockBackend::new(&[(&[0x6e], &[0xae])]);
        let mut card = Card::new(&mb);
        assert!(card.get_free_memory().await.is_err());
    }

    #[tokio::test]
    async fn test_free_memory_short() {
        let mb = MockBackend::new(&[(&[0x6e], &[0x00])]);
        let mut card = Card::new(&mb);
        assert!(card.get_free_memory().await.is_err());
    }
}

// vim: foldmethod=marker
