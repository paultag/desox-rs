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
    Error, FileCommunication, FileId, FilePermissions, FileSettings, FileType, Instruction,
    StatusCode, U24,
    client::{
        Authenticated, AuthenticationState, Card, CardIoDefault, Unauthenticated, command,
        command_cmac_de_minimis, command_de_minimis, command_encrypted_request_de_minimis,
        command_encrypted_response,
    },
    io,
};

/// Trait to handle file i/o (be it authenticated or not!) -- this is a trait
/// because the specific way we talk to a file changes depending on
/// authentication.
pub trait FileIo<'card, IoBackendT>
where
    IoBackendT: io::Backend,
{
    /// Read from a file
    fn read_file_at<'a>(
        &mut self,
        out: &'a mut [u8],
        file_id: FileId,
        communication: FileCommunication,
        offset: u32,
        length: u32,
    ) -> impl Future<Output = Result<&'a [u8], Error<IoBackendT::Error>>>;

    /// Write to a file
    fn write_file_at(
        &mut self,
        file_id: FileId,
        communication: FileCommunication,
        offset: u32,
        data: &[u8],
    ) -> impl Future<Output = Result<(), Error<IoBackendT::Error>>>;
}

impl<'card, IoBackendT> FileIo<'card, IoBackendT> for Card<'card, IoBackendT, Unauthenticated>
where
    IoBackendT: io::Backend,
{
    async fn read_file_at<'a>(
        &mut self,
        out: &'a mut [u8],
        file_id: FileId,
        communication: FileCommunication,
        offset: u32,
        length: u32,
    ) -> Result<&'a [u8], Error<IoBackendT::Error>> {
        let (status_code, response) = match communication {
            FileCommunication::Plain | FileCommunication::Cmac => {
                command!(self, out, {
                    instruction: Instruction = Instruction::ReadDataFile,
                    file_id: u8 = file_id,
                    offset: [u8; 3] = U24::to_le_bytes(offset),
                    length: [u8; 3] = U24::to_le_bytes(length)
                }, 8, [])
            }
            FileCommunication::Encrypted => {
                return Err(Error::BadFileCommunication);
            }
        };

        #[cfg(feature = "tracing")]
        tracing::debug!(
            method = "read_file_at",
            status_code = format!("{:?}", status_code)
        );

        if status_code != StatusCode::Ack {
            return Err(Error::BadStatusCode(status_code));
        }

        Ok(response)
    }

    async fn write_file_at(
        &mut self,
        file_id: FileId,
        communication: FileCommunication,
        offset: u32,
        data: &[u8],
    ) -> Result<(), Error<IoBackendT::Error>> {
        let (status_code, response) = match communication {
            FileCommunication::Plain => {
                command_de_minimis!(self, {
            instruction: Instruction = Instruction::WriteDataFile,
            file_id: u8 = file_id,
            offset: [u8; 3] = U24::to_le_bytes(offset),
            size: [u8; 3] = U24::to_le_bytes(data.len() as u32)
        }, 8, [data])
            }
            FileCommunication::Cmac | FileCommunication::Encrypted => {
                return Err(Error::BadFileCommunication);
            }
        };

        #[cfg(feature = "tracing")]
        tracing::debug!(
            method = "write_file_at",
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

impl<'card, IoBackendT> FileIo<'card, IoBackendT> for Card<'card, IoBackendT, Authenticated>
where
    IoBackendT: io::Backend,
{
    /// Read from a file
    async fn read_file_at<'a>(
        &mut self,
        out: &'a mut [u8],
        file_id: FileId,
        communication: FileCommunication,
        offset: u32,
        length: u32,
    ) -> Result<&'a [u8], Error<IoBackendT::Error>> {
        let (status_code, response) = match communication {
            FileCommunication::Plain | FileCommunication::Cmac => {
                command!(self, out, {
                    instruction: Instruction = Instruction::ReadDataFile,
                    file_id: u8 = file_id,
                    offset: [u8; 3] = U24::to_le_bytes(offset),
                    length: [u8; 3] = U24::to_le_bytes(length)
                }, 8, [])
            }
            FileCommunication::Encrypted => {
                command_encrypted_response!(self, out, {
                    instruction: Instruction = Instruction::ReadDataFile,
                    file_id: u8 = file_id,
                    offset: [u8; 3] = U24::to_le_bytes(offset),
                    length: [u8; 3] = U24::to_le_bytes(length)
                }, 8, [])
            }
        };

        #[cfg(feature = "tracing")]
        tracing::debug!(
            method = "read_file_at",
            status_code = format!("{:?}", status_code)
        );

        let n = response.len().min(length as usize);
        if n < (length as usize) {
            return Err(Error::PartialRead);
        }

        // we know the size, so we don't pad/unpad here.
        let response = &response[..n];

        if status_code != StatusCode::Ack {
            return Err(Error::BadStatusCode(status_code));
        }

        Ok(response)
    }

    /// Create a file within the currently open application.
    async fn write_file_at(
        &mut self,
        file_id: FileId,
        communication: FileCommunication,
        offset: u32,
        data: &[u8],
    ) -> Result<(), Error<IoBackendT::Error>> {
        let (status_code, response) = match communication {
            FileCommunication::Plain => {
                command_de_minimis!(self, {
            instruction: Instruction = Instruction::WriteDataFile,
            file_id: u8 = file_id,
            offset: [u8; 3] = U24::to_le_bytes(offset),
            size: [u8; 3] = U24::to_le_bytes(data.len() as u32)
        }, 8, [data])
            }
            FileCommunication::Cmac => {
                command_cmac_de_minimis!(self, {
            instruction: Instruction = Instruction::WriteDataFile,
            file_id: u8 = file_id,
            offset: [u8; 3] = U24::to_le_bytes(offset),
            size: [u8; 3] = U24::to_le_bytes(data.len() as u32)
        }, 8, [data])
            }
            FileCommunication::Encrypted => {
                command_encrypted_request_de_minimis!(self, {
            instruction: Instruction = Instruction::WriteDataFile,
            file_id: u8 = file_id,
            offset: [u8; 3] = U24::to_le_bytes(offset),
            size: [u8; 3] = U24::to_le_bytes(data.len() as u32)
        }, 8, [data])
            }
        };

        #[cfg(feature = "tracing")]
        tracing::debug!(
            method = "write_file_at",
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
    use crate::{Card, FileCommunication, FileIo, io::MockBackend};

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

    #[tokio::test]
    async fn test_unauth_encrypted_file_read() {
        let mb = MockBackend::new(&[]);
        let mut out = [0; 0xffff];
        let mut card = Card::new(&mb);

        assert!(
            card.read_file_at(&mut out, 0x00, FileCommunication::Encrypted, 0, 1024)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_unauth_encrypted_file_write() {
        let mb = MockBackend::new(&[]);
        let mut card = Card::new(&mb);

        assert!(
            card.write_file_at(0x00, FileCommunication::Encrypted, 0, b"hack the planet")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_unauth_cmac_file_write() {
        let mb = MockBackend::new(&[]);
        let mut card = Card::new(&mb);

        assert!(
            card.write_file_at(0x00, FileCommunication::Cmac, 0, b"hack the planet")
                .await
                .is_err()
        );
    }
}

// vim: foldmethod=marker
