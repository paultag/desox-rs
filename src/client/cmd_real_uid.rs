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
    Error, Instruction, StatusCode, Uid,
    client::{Authenticated, Card, Session},
    io,
};

impl<'card, IoBackendT> Card<'card, IoBackendT, Authenticated>
where
    IoBackendT: io::Backend,
{
    /// Get the MiFare card's globally unique 7-byte UID. This can only
    /// be done while authenticated -- and is sent back to us encrypted.
    pub async fn get_uid(&mut self, out: &mut [u8]) -> Result<Uid, Error<IoBackendT::Error>> {
        let (status_code, response) = match &mut self.authentication.session {
            Session::Des { keying, .. } => {
                io::plain_out_encrypted_in(
                    &self.card,
                    keying,
                    out,
                    &[Instruction::GetUid as u8],
                    &[],
                )
                .await?
            }
            Session::Aes { keying, .. } => {
                io::plain_out_encrypted_in(
                    &self.card,
                    keying,
                    out,
                    &[Instruction::GetUid as u8],
                    &[],
                )
                .await?
            }
        };

        let response = &response[..7 + 4];
        let response = io::check_crc32(response, &[&[status_code.into()]])?;

        if status_code != StatusCode::Ack {
            return Err(Error::BadStatusCode);
        }
        let uid: &Uid = response.try_into().map_err(|_| Error::BadSize)?;
        Ok(*uid)
    }
}

// vim: foldmethod=marker
