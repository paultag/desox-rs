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
    CopyToSlice, Error, Instruction, Padding, StatusCode,
    client::KeyingState,
    crc32,
    crypto::{Backend as CryptoBackend, BackendDecryptor, BackendEncryptor, Scheme},
    io::{Backend as IoBackend, plain_multi},
    std::fmt::Debug,
};

/// Exchange a plain message, expecting an encrypted message in reply.
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

    ks.generate_cmac(header, data);

    let (status_code, data) = plain_multi(backend, output, header, data).await?;
    let n = data.len();
    let data = &mut output[..n];

    if !data.len().is_multiple_of(KEY_SIZE) {
        return Err(Error::BadSize);
    }

    let iv: [u8; KEY_SIZE] = data[data.len() - KEY_SIZE..].try_into().unwrap();

    let mut decryptor = ks.decryptor();
    decryptor.decrypt(data);

    let data = Padding::unpad(data);

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
    // first let's compute our crc32. we're going to include this at the
    // very end of the encrypted message. doing this now means we can
    // handle the streaming bits ourselves and bypass using plain_multi,
    // and re-implement the AF logic here too.

    let crc = crc32(header, data).to_le_bytes();
    let mut data = data.to_vec();
    data.push(&crc);
    let data = &data;

    let (mut data, _data_len) = {
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

                    // Awkwardly, not padded in the conventional way?
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
                ks.set_iv(iv);
                let output = ks.validate_cmac(&output[..n], Some(&[status_code.into()]))?;
                return Ok((status_code, output));
            }
        }
    }
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
