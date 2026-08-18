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

use crate::{Error, StatusCode, client::KeyingState, crypto, io, std::fmt::Debug};

/// Exchange a CMAC signed message with the Card.
pub async fn plain_out_cmac_in<'a, const KEY_SIZE: usize, BackendT, AlgorithmT>(
    backend: &BackendT,
    ks: &mut KeyingState<KEY_SIZE, AlgorithmT>,
    output: &'a mut [u8],
    header: &[u8],
    data: &[&[u8]],
) -> Result<(StatusCode, &'a [u8]), Error<BackendT::Error>>
where
    BackendT: io::Backend,
    BackendT::Error: Debug,
    crypto::Scheme<KEY_SIZE, AlgorithmT>: crypto::Backend<KEY_SIZE>,
{
    #[cfg(feature = "tracing")]
    tracing::debug!(
        direction = "request",
        method = "plain",
        header = hex::encode(header),
        data = data.iter().map(hex::encode).collect::<String>(),
    );

    ks.generate_cmac(header, data);

    let (status_code, data) = io::plain_multi(backend, output, header, data).await?;
    if status_code != StatusCode::Ack {
        return Ok((status_code, &[]));
    }

    let data = ks.validate_cmac(data, Some(&[status_code.into()]))?;

    #[cfg(feature = "tracing")]
    tracing::debug!(
        direction = "response",
        method = "cmac",
        status_code = format!("{:?}", status_code),
        data = hex::encode(data),
    );

    Ok((status_code, data))
}

/// Exchange a CMAC signed message with the Card, both out and in.
pub async fn cmac_out_cmac_in<'a, const KEY_SIZE: usize, BackendT, AlgorithmT>(
    backend: &BackendT,
    ks: &mut KeyingState<KEY_SIZE, AlgorithmT>,
    output: &'a mut [u8],
    header: &[u8],
    data: &[&[u8]],
) -> Result<(StatusCode, &'a [u8]), Error<BackendT::Error>>
where
    BackendT: io::Backend,
    BackendT::Error: Debug,
    crypto::Scheme<KEY_SIZE, AlgorithmT>: crypto::Backend<KEY_SIZE>,
{
    let cmac = ks.generate_cmac_short(header, data);
    let mut data = data.to_vec();
    data.push(&cmac);

    #[cfg(feature = "tracing")]
    tracing::debug!(
        direction = "request",
        method = "cmac",
        header = hex::encode(header),
        data = data.iter().map(hex::encode).collect::<String>(),
    );

    let (status_code, data) = io::plain_multi(backend, output, header, &data).await?;

    if status_code != StatusCode::Ack {
        return Ok((status_code, &[]));
    }

    let data = ks.validate_cmac(data, Some(&[status_code.into()]))?;

    #[cfg(feature = "tracing")]
    tracing::debug!(
        direction = "response",
        method = "cmac",
        status_code = format!("{:?}", status_code),
        data = hex::encode(data),
    );

    Ok((status_code, data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Instruction,
        client::AuthenticateExt,
        crypto::Backend as CryptoBackend,
        io::{mock_backend, plain},
    };
    use hex_literal::hex;

    #[tokio::test]
    async fn test_capture_fc() {
        let mut sks = KeyingState::<8, _>::new(hex!("BA 02 0A 16 EC E6 1C 12"));

        let mb = mock_backend!(
            // format card
            ("FC", "00 A7 0A 5C 88 36 14 1E 82")
        );

        let mut output = [0; 0xff];
        let (status_code, response) = plain_out_cmac_in(
            &mb,
            &mut sks,
            &mut output,
            &[Instruction::FormatCard as u8],
            &[],
        )
        .await
        .unwrap();
        assert_eq!(StatusCode::Ack, status_code);
        assert_eq!(&hex!(""), response);
    }

    #[tokio::test]
    async fn test_capture_card_info_over_and_over() {
        let mb = mock_backend!(
            // Card is unauthenticated here.
            //
            // Get card info
            ("60", "AF 04 01 01 33 00 18 05"),
            ("AF", "AF 04 01 01 03 00 18 05"),
            ("AF", "00 04 4B 1F 9A DD 1E 90 21 13 62 30 30 40 24"),
            // DES authentication, key 0
            //
            // Card is now Authenticated.
            ("1A 00", "AF 32 C7 09 D5 A4 C1 1F 98"),
            (
                "AF F1 87 90 79 A7 6D BE 43 F6 A8 C4 BA 37 A6 63 43",
                "00 07 45 0F E4 E5 75 30 5D"
            ),
            // Get card info (CMAC signed)
            ("60", "AF 04 01 01 33 00 18 05"),
            ("AF", "AF 04 01 01 03 00 18 05"),
            (
                "AF",
                "00 04 4B 1F 9A DD 1E 90 21 13 62 30 30 40 24 82 74 08 E9 35 1B 31 5C"
            ),
            // Get card info (CMAC signed)
            ("60", "AF 04 01 01 33 00 18 05"),
            ("AF", "AF 04 01 01 03 00 18 05"),
            (
                "AF",
                "00 04 4B 1F 9A DD 1E 90 21 13 62 30 30 40 24 39 F6 30 E2 AE 63 64 B5"
            ),
            // Get card info (CMAC signed)
            ("60", "AF 04 01 01 33 00 18 05"),
            ("AF", "AF 04 01 01 03 00 18 05"),
            (
                "AF",
                "00 04 4B 1F 9A DD 1E 90 21 13 62 30 30 40 24 1F 93 11 F9 4A 6B 26 BB"
            )
        );

        // Hardcoded output based on the above
        let card_version = hex!(
            "04 01 01 33 00 18 05 04 01 01 03 00 18 05 04 4B 1F 9A DD 1E 90 21 13 62 30 30 40 24"
        );

        let mut output = [0; 0xff];
        let (status_code, response) = plain(&mb, &mut output, &[Instruction::GetVersionInfo as u8])
            .await
            .unwrap();

        assert_eq!(StatusCode::Ack, status_code);
        assert_eq!(&card_version, response);

        let session_key = mb
            .authenticate_with_rnd_a(0x00, [0x00; 8], Some(hex!("00 83 6D 4B F5 AA 65 27")))
            .await
            .unwrap();
        assert_eq!(hex!("00 82 6C 4A 02 B2 C2 70"), session_key);

        let mut ks = KeyingState::<8, _>::new(session_key);
        assert_eq!(&[0; 8], ks.get_iv());

        output.fill(0x00);
        let (status_code, response) = plain_out_cmac_in(
            &mb,
            &mut ks,
            &mut output,
            &[Instruction::GetVersionInfo as u8],
            &[],
        )
        .await
        .unwrap();
        assert_eq!(StatusCode::Ack, status_code);
        assert_eq!(&card_version, response);
    }
}

// vim: foldmethod=marker
