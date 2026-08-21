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
    Authenticated, Card, CardIoDefault, Error, FileCommunication, FileId, Instruction, StatusCode,
    U24, Unauthenticated, command, command_cmac_de_minimis, command_de_minimis,
    command_encrypted_request_de_minimis, command_encrypted_response, io,
};

/// Trait to handle file i/o (be it authenticated or not!) -- this is a trait
/// because the specific way we talk to a file changes depending on
/// authentication.
pub trait FileIo<IoBackendT>
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

impl<IoBackendT> FileIo<IoBackendT> for Card<IoBackendT, Unauthenticated>
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
            file_id = file_id,
            communication = format!("{:?}", communication),
            offset = offset,
            length = length,
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
            file_id = file_id,
            communication = format!("{:?}", communication),
            offset = offset,
            data = hex::encode(data),
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

impl<IoBackendT> FileIo<IoBackendT> for Card<IoBackendT, Authenticated>
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
            file_id = file_id,
            communication = format!("{:?}", communication),
            offset = offset,
            length = length,
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
            file_id = file_id,
            communication = format!("{:?}", communication),
            offset = offset,
            data = hex::encode(data),
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

#[cfg(test)]
mod tests {
    use crate::{Card, FileCommunication, FileIo, io::MockBackend};

    #[tokio::test]
    async fn test_unauth_encrypted_file_read() {
        let mut mb = MockBackend::new(&[]);
        let mut out = [0; 0xffff];
        let mut card = Card::new(&mut mb);

        assert!(
            card.read_file_at(&mut out, 0x00, FileCommunication::Encrypted, 0, 1024)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_unauth_encrypted_file_write() {
        let mut mb = MockBackend::new(&[]);
        let mut card = Card::new(&mut mb);

        assert!(
            card.write_file_at(0x00, FileCommunication::Encrypted, 0, b"hack the planet")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_unauth_cmac_file_write() {
        let mut mb = MockBackend::new(&[]);
        let mut card = Card::new(&mut mb);

        assert!(
            card.write_file_at(0x00, FileCommunication::Cmac, 0, b"hack the planet")
                .await
                .is_err()
        );
    }
}

// vim: foldmethod=marker
