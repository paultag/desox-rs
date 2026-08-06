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
    StatusCode,
    client::{
        Authenticated, AuthenticationState, Card, CardIoDefault, Unauthenticated, command,
        command_cmac, command_encrypted_request, command_encrypted_response,
    },
    io,
};

trait ToU24 {
    fn to_le_bytes(self) -> [u8; 3];
}

impl ToU24 for u32 {
    fn to_le_bytes(self) -> [u8; 3] {
        let size: [u8; 4] = u32::to_le_bytes(self);
        let size: [u8; 3] = [size[0], size[1], size[2]];
        size
    }
}

impl<'card, IoBackendT> Card<'card, IoBackendT, Unauthenticated>
where
    IoBackendT: io::Backend,
{
    /// Read from a file
    pub async fn read_file_at<'a>(
        &mut self,
        out: &'a mut [u8],
        file_id: FileId,
        type_: FileType,
        communication: FileCommunication,
        offset: u32,
        length: u32,
    ) -> Result<&'a [u8], Error<IoBackendT::Error>> {
        #[expect(irrefutable_let_patterns)]
        let FileType::Data = type_ else {
            unimplemented!();
        };

        let (status_code, response) = match communication {
            FileCommunication::Plain | FileCommunication::Cmac => {
                command!(self, out, {
                    instruction: Instruction = Instruction::ReadDataFile,
                    file_id: u8 = file_id,
                    offset: [u8; 3] = ToU24::to_le_bytes(offset),
                    length: [u8; 3] = ToU24::to_le_bytes(length)
                }, 8, [])
            }
            FileCommunication::Encrypted => {
                return Err(Error::BadFileCommunication);
            }
        };

        if status_code != StatusCode::Ack {
            return Err(Error::BadStatusCode);
        }

        Ok(response)
    }
}

impl<'card, IoBackendT> Card<'card, IoBackendT, Authenticated>
where
    IoBackendT: io::Backend,
{
    /// Create a file within the currently open application.
    pub async fn create_file(
        &mut self,
        out: &mut [u8],
        file_id: FileId,
        settings: FileSettings,
    ) -> Result<(), Error<IoBackendT::Error>> {
        let FileSettings {
            type_,
            communication,
            permissions,
            size,
        } = settings;

        #[expect(irrefutable_let_patterns)]
        let FileType::Data = type_ else {
            unimplemented!();
        };

        let (status_code, response) = command!(self, out, {
            instruction: Instruction = Instruction::CreateDataFile,
            file_id: u8 = file_id,
            communication: u8 = communication.as_u8(),
            permissions: [u8; 2] = permissions.as_bytes()?,
            size: [u8; 3] = ToU24::to_le_bytes(size)
        }, 8, []);

        if !response.is_empty() {
            return Err(Error::BadSize);
        };

        if status_code != StatusCode::Ack {
            return Err(Error::BadStatusCode);
        }

        Ok(())
    }

    /// Create a file within the currently open application.
    pub async fn write_file_at(
        &mut self,
        out: &mut [u8],
        file_id: FileId,
        type_: FileType,
        communication: FileCommunication,
        offset: u32,
        data: &[u8],
    ) -> Result<(), Error<IoBackendT::Error>> {
        #[expect(irrefutable_let_patterns)]
        let FileType::Data = type_ else {
            unimplemented!();
        };

        let (status_code, response) = match communication {
            FileCommunication::Plain => {
                command!(self, out, {
            instruction: Instruction = Instruction::WriteDataFile,
            file_id: u8 = file_id,
            offset: [u8; 3] = ToU24::to_le_bytes(offset),
            size: [u8; 3] = ToU24::to_le_bytes(data.len() as u32)
        }, 8, [data])
            }
            FileCommunication::Cmac => {
                command_cmac!(self, out, {
            instruction: Instruction = Instruction::WriteDataFile,
            file_id: u8 = file_id,
            offset: [u8; 3] = ToU24::to_le_bytes(offset),
            size: [u8; 3] = ToU24::to_le_bytes(data.len() as u32)
        }, 8, [data])
            }
            FileCommunication::Encrypted => {
                command_encrypted_request!(self, out, {
            instruction: Instruction = Instruction::WriteDataFile,
            file_id: u8 = file_id,
            offset: [u8; 3] = ToU24::to_le_bytes(offset),
            size: [u8; 3] = ToU24::to_le_bytes(data.len() as u32)
        }, 8, [data])
            }
        };

        if !response.is_empty() {
            return Err(Error::BadSize);
        };

        if status_code != StatusCode::Ack {
            return Err(Error::BadStatusCode);
        }

        Ok(())
    }

    /// Read from a file
    pub async fn read_file_at<'a>(
        &mut self,
        out: &'a mut [u8],
        file_id: FileId,
        type_: FileType,
        communication: FileCommunication,
        offset: u32,
        length: u32,
    ) -> Result<&'a [u8], Error<IoBackendT::Error>> {
        #[expect(irrefutable_let_patterns)]
        let FileType::Data = type_ else {
            unimplemented!();
        };

        let (status_code, response) = match communication {
            FileCommunication::Plain | FileCommunication::Cmac => {
                command!(self, out, {
                    instruction: Instruction = Instruction::ReadDataFile,
                    file_id: u8 = file_id,
                    offset: [u8; 3] = ToU24::to_le_bytes(offset),
                    length: [u8; 3] = ToU24::to_le_bytes(length)
                }, 8, [])
            }
            FileCommunication::Encrypted => {
                command_encrypted_response!(self, out, {
                    instruction: Instruction = Instruction::ReadDataFile,
                    file_id: u8 = file_id,
                    offset: [u8; 3] = ToU24::to_le_bytes(offset),
                    length: [u8; 3] = ToU24::to_le_bytes(length)
                }, 8, [])
            }
        };

        if status_code != StatusCode::Ack {
            return Err(Error::BadStatusCode);
        }

        Ok(response)
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

        if status_code != StatusCode::Ack {
            return Err(Error::BadStatusCode);
        }

        Ok(response)
    }
    /// Read from a file
    pub async fn get_file_settings(
        &mut self,
        out: &mut [u8],
        file_id: FileId,
    ) -> Result<FileSettings, Error<IoBackendT::Error>> {
        let (status_code, response) = command!(self, out, {
            instruction: Instruction = Instruction::GetFileSettings,
            file_id: u8 = file_id
        }, 2, []);

        if status_code != StatusCode::Ack {
            return Err(Error::BadStatusCode);
        }

        if response.len() != 7 {
            return Err(Error::BadSize);
        };

        let type_ = FileType::from_u8(response[0])?;
        let communication = FileCommunication::from_u8(response[1])?;
        let permissions = FilePermissions::from_bytes([response[2], response[3]])?;
        let size = u32::from_le_bytes([response[4], response[5], response[6], 0x00]);

        Ok(FileSettings {
            type_,
            communication,
            permissions,
            size,
        })
    }
}

// vim: foldmethod=marker
