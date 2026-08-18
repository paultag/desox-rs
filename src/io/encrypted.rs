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
    CopyToSlice, Error, Instruction, StatusCode,
    client::KeyingState,
    crypto::{Backend as CryptoBackend, BackendDecryptor, BackendEncryptor, Scheme},
    io::{Backend as IoBackend, plain_multi},
    std::fmt::Debug,
};

/// Exchange a plain message, expecting an encrypted message in reply.
///
/// We don't pad/unpad in here, since this is technically a higher-level
/// concern.
pub async fn plain_out_encrypted_in<'a, const KEY_SIZE: usize, BackendT, AlgorithmT>(
    backend: &BackendT,
    ks: &mut KeyingState<KEY_SIZE, AlgorithmT>,
    output: &'a mut [u8],
    header: &[u8],
    data: &[&[u8]],
) -> Result<(StatusCode, &'a [u8]), Error<BackendT::Error>>
where
    BackendT: IoBackend,
    BackendT::Error: Debug,
    Scheme<KEY_SIZE, AlgorithmT>: CryptoBackend<KEY_SIZE>,
{
    // we need to generate the CMAC for the input to ratchet internal
    // state forward.

    #[cfg(feature = "tracing")]
    tracing::trace!(
        direction = "request",
        method = "plain",
        header = hex::encode(header),
        data = data.iter().map(hex::encode).collect::<String>(),
    );

    ks.generate_cmac(header, data);

    let (status_code, data) = plain_multi(backend, output, header, data).await?;
    let n = data.len();
    let data = &mut output[..n];

    #[cfg(feature = "tracing")]
    tracing::trace!(
        direction = "response",
        method = "encrypted(ciphertext)",
        data = hex::encode(&data),
    );

    if !data.len().is_multiple_of(KEY_SIZE) {
        return Err(Error::BadSize);
    }

    let iv: [u8; KEY_SIZE] = data[data.len() - KEY_SIZE..].try_into().unwrap();

    let mut decryptor = ks.decryptor();
    decryptor.decrypt(data);

    #[cfg(feature = "tracing")]
    tracing::trace!(
        direction = "response",
        method = "encrypted(plaintext)",
        status_code = format!("{:?}", status_code),
        data = hex::encode(&data),
    );

    ks.set_iv(iv);

    Ok((status_code, data))
}

/// Exchange a encrypted message, expecting a plain message in reply.
///
/// This assumes the header is "in the clear", and the data we're sending
/// is encrypted. This also assumes a CRC is included.
pub async fn encrypted_out_plain_in<'a, const KEY_SIZE: usize, BackendT, AlgorithmT>(
    backend: &BackendT,
    ks: &mut KeyingState<KEY_SIZE, AlgorithmT>,
    output: &'a mut [u8],
    header: &[u8],
    data: &[&[u8]],
) -> Result<(StatusCode, &'a [u8]), Error<BackendT::Error>>
where
    BackendT: IoBackend,
    BackendT::Error: Debug,
    Scheme<KEY_SIZE, AlgorithmT>: CryptoBackend<KEY_SIZE>,
{
    #[cfg(feature = "tracing")]
    tracing::trace!(
        direction = "request",
        method = "encrypted(plaintext)",
        header = hex::encode(header),
        data = data.iter().map(hex::encode).collect::<String>(),
    );

    let (mut data, data_len) = {
        let data_len = data.iter().fold(0, |n, data| n + data.len());
        (data.iter().flat_map(|v| v.iter()), data_len)
    };

    let mut command = header;
    let mut buf_in = [0; 0xff]; // used to create a command
    let mut buf_out = [0; 0xff]; // used to write responses to
    let mut n = 0;
    let block_size = KEY_SIZE * 2;
    let mut iv = [0; KEY_SIZE];

    let mut encryptor = ks.encryptor();

    if data_len > 0 && command.len() + data_len <= 59 {
        // Special case; usually what this code will do is send the header,
        // we expect an 0xAF back, and we'll continue sending encrypted data.
        //
        // This is a fine assumption for writing data, but things like changing
        // a password need to be a single command. I don't love it, but we
        // can go ahead and just omnibus this whole thing if the command
        // is short enough.

        buf_in[..command.len()].copy_from_slice(command);

        let buf_data = &mut buf_in[command.len()..];
        let Some(n) = (&mut data).take(59).copied().copy_to_slice(buf_data) else {
            unreachable!();
        };

        let block_size = if n.is_multiple_of(KEY_SIZE) {
            n
        } else {
            n + KEY_SIZE - (n % KEY_SIZE)
        };

        let buf_data = &mut buf_data[..block_size];
        buf_data[n..].fill(0x00);
        encryptor.encrypt(buf_data);
        iv = buf_data[buf_data.len() - KEY_SIZE..].try_into().unwrap();
        command = &buf_in[..command.len() + block_size];
    }

    loop {
        let (status_code, response) = backend
            .exchange(&mut buf_out, command)
            .await
            .map_err(Error::IoBackend)?;

        output[n..(n + response.len())].copy_from_slice(response);
        n += response.len();

        match status_code {
            StatusCode::AdditionalData => {
                buf_in[0] = Instruction::AdditionalData as u8;

                if let Some(n) = (&mut data)
                    .take(block_size)
                    .copied()
                    .copy_to_slice(&mut buf_in[1..])
                {
                    // if we have more "outgoing" data, we need to pipe that
                    // out along with the 0xAF after encrypting it.

                    let block_size = if n.is_multiple_of(KEY_SIZE) {
                        n
                    } else {
                        n + KEY_SIZE - (n % KEY_SIZE)
                    };

                    // Awkwardly, not padded in the conventional way; likely
                    // because the size is already known due to the
                    // (UNENCRYPTED!) header.

                    let buf_data = &mut buf_in[1..(block_size + 1)];
                    buf_data[n..].fill(0x00);
                    encryptor.encrypt(buf_data);

                    iv = buf_data[buf_data.len() - KEY_SIZE..].try_into().unwrap();
                    command = &buf_in[..(block_size + 1)];
                } else {
                    command = &buf_in[..1];
                }
                continue;
            }
            _ => {
                #[cfg(feature = "tracing")]
                tracing::trace!(
                    direction = "response",
                    method = "plain",
                    status_code = format!("{:?}", status_code),
                    data = hex::encode(&output[..n]),
                );
                ks.set_iv(iv);
                return Ok((status_code, &output[..n]));
            }
        }
    }
}

/// Exchange a encrypted message, expecting a plain message in reply.
///
/// This assumes the header is "in the clear", and the data we're sending
/// is encrypted. This also assumes a CRC is included.
pub async fn encrypted_out_cmac_in<'a, const KEY_SIZE: usize, BackendT, AlgorithmT>(
    backend: &BackendT,
    ks: &mut KeyingState<KEY_SIZE, AlgorithmT>,
    output: &'a mut [u8],
    header: &[u8],
    data: &[&[u8]],
) -> Result<(StatusCode, &'a [u8]), Error<BackendT::Error>>
where
    BackendT: IoBackend,
    BackendT::Error: Debug,
    Scheme<KEY_SIZE, AlgorithmT>: CryptoBackend<KEY_SIZE>,
{
    let (status_code, response) = encrypted_out_plain_in(backend, ks, output, header, data).await?;
    let output = ks.validate_cmac(response, Some(&[status_code.into()]))?;
    Ok((status_code, output))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Instruction, io::mock_backend};
    use hex_literal::hex;

    #[tokio::test]
    async fn test_capture_real_uid() {
        let mut ks = KeyingState::<8, _>::new(hex!("A0 CE B0 F4 08 D4 60 DE"));

        let mb = mock_backend!(("51", "00 50 1F 93 0A 8B 90 A0 80 EC 9F B1 BA 83 89 2E A3"));

        let mut output = [0; 0xff];
        let (status_code, response) =
            plain_out_encrypted_in(&mb, &mut ks, &mut output, &[Instruction::GetUid as u8], &[])
                .await
                .unwrap();
        assert_eq!(StatusCode::Ack, status_code);
        assert_eq!(16, response.len());
        assert_eq!(&hex!("04 4B 1F 9A DD 1E 90"), &response[..7]);
    }
}

// vim: foldmethod=marker
