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

use super::Handshake;
use crate::{
    Error, Instruction, StatusCode,
    crypto::{Backend, Kdf, Scheme},
    io,
};

/// Indicates what [Instruction] to use when initiating the Authentication
/// flow for the provided algorithm.
pub trait Initiate {
    /// Return the [Instruction].
    fn instruction() -> Instruction;
}

impl Initiate for Scheme<8, des::Des> {
    fn instruction() -> Instruction {
        Instruction::AuthenticateDes
    }
}

impl Initiate for Scheme<16, aes::Aes128> {
    fn instruction() -> Instruction {
        Instruction::AuthenticateAes
    }
}

/// Authentication ext-trait to handle the i/o communication with the
/// backend.
pub trait AuthenticateExt<const KEY_SIZE: usize, AlgorithmT>
where
    Scheme<KEY_SIZE, AlgorithmT>: Backend<KEY_SIZE>,
    Self: io::Backend,
{
    /// Do the authentication flow
    fn authenticate_with_rnb_a(
        &self,
        key_id: u8,
        key: [u8; KEY_SIZE],
        rnd_a: Option<[u8; KEY_SIZE]>,
    ) -> impl Future<Output = Result<[u8; KEY_SIZE], Error<<Self as io::Backend>::Error>>>;

    /// Do the authentication flow
    fn authenticate(
        &self,
        key_id: u8,
        key: [u8; KEY_SIZE],
    ) -> impl Future<Output = Result<[u8; KEY_SIZE], Error<<Self as io::Backend>::Error>>> {
        self.authenticate_with_rnb_a(key_id, key, None)
    }
}

impl<const KEY_SIZE: usize, AlgorithmT, IoBackendT> AuthenticateExt<KEY_SIZE, AlgorithmT>
    for IoBackendT
where
    IoBackendT: io::Backend,
    ([u8; KEY_SIZE], [u8; KEY_SIZE]): Kdf<KEY_SIZE>,
    Scheme<KEY_SIZE, AlgorithmT>: Backend<KEY_SIZE>,
    Scheme<KEY_SIZE, AlgorithmT>: Initiate,
{
    async fn authenticate_with_rnb_a(
        &self,
        key_id: u8,
        key: [u8; KEY_SIZE],
        rnd_a: Option<[u8; KEY_SIZE]>,
    ) -> Result<[u8; KEY_SIZE], Error<<IoBackendT as io::Backend>::Error>> {
        let mut buf_command = [0; 0xff];
        let mut buf_response = [0; 0xff];

        let (handshake, command) =
            Handshake::<KEY_SIZE, AlgorithmT, _>::begin(&mut buf_command, key, key_id);

        let (status_code, response) = self
            .exchange(&mut buf_response, command)
            .await
            .map_err(Error::IoBackend)?;

        if status_code != StatusCode::AdditionalData {
            return Err(Error::BadStatusCode(status_code));
        }

        let (handshake, command) = if let Some(rnd_a) = rnd_a {
            handshake.rnd_b_with_key(&mut buf_command, response, rnd_a)
        } else {
            handshake.rnd_b(&mut buf_command, response)
        }?;

        let (status_code, response) = self
            .exchange(&mut buf_response, command)
            .await
            .map_err(Error::IoBackend)?;

        if status_code != StatusCode::Ack {
            return Err(Error::BadStatusCode(status_code));
        }

        Ok(handshake.complete(response)?.into_key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::mock_backend;
    use hex_literal::hex;

    macro_rules! simulate_handshake {
        (
            $name:ident,
            $key_size:literal,
            $crypto:path,
            key = $key:expr,
            rnd_a = $rnd_a:expr,
            session_key = $session_key:expr,
            ( $( ( $in:expr, $out:expr ) ),* )
        ) => {
            #[tokio::test]
            async fn $name() {
                let mb = mock_backend!( $( ($in, $out) ),* );
                let key = mb.authenticate_with_rnb_a(0x00, hex!($key), Some(hex!($rnd_a))).await.unwrap();
                assert_eq!(hex!($session_key), key);
            }
        };
    }

    simulate_handshake!(
        test_capture_des,
        8,
        des::Des,
        key = "00 00 00 00 00 00 00 00",
        rnd_a = "A0 CF B1 F4 35 29 4B 9B",
        session_key = "A0 CE B0 F4 08 D4 60 DE",
        (
            (
                "1A 00",                      // host to card, start auth
                "AF BE 06 BE 0C F7 19 E2 92"  // card to host; encrypted RndB
            ),
            (
                "AF DB EB DB 42 F0 B8 87 0C F5 98 99 56 2A 44 C2 77", // host to card, RndAB
                "00 8F 72 31 73 06 1C FF 81"                          // card to host, RndA
            )
        )
    );

    simulate_handshake!(
        test_capture_aes,
        16,
        aes::Aes128,
        key = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        rnd_a = "DE 04 17 85 C0 C0 45 76 12 99 A6 67 C4 EB A7 EE",
        session_key = "DE 04 17 85 F5 9C 23 F5 C4 EB A7 EE B7 89 78 55",
        (
            (
                "AA 00",                                              // host to card, start auth
                "AF BC 1C DE 5D 71 09 7F 97 DF E7 0D 24 A8 7A 4A 50"  // card to host, encrypted RndB
            ),
            (
                "AF 3F D0 A9 C9 88 69 4E BB 12 35 49 C6 8D D6 61 B5 F9 69 6C 3D A4 6D 56 B7 FC 3B B4 8A 3B 6E A1 2F", // host to card, RndAB
                "00 E7 60 EB 7A 31 DE 62 D5 C2 95 A2 D8 94 CA 18 14" // card to host, RndA
            )
        )
    );
}

// vim: foldmethod=marker
