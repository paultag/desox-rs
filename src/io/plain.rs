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

use super::Backend;
use crate::{CopyToSlice, Error, Instruction, StatusCode};

const MAX_SIZE: usize = 59;

/// Exchange a plain message with the underlying backend. This is how we
/// communicate with a card when there's no shared keying.
///
/// If the reply is for more data, we will continue to ask for data
/// until we see the end of the data. If this is not desired, you may
/// need to interact with the [Backend] directly.
pub async fn plain<'a, BackendT>(
    backend: &BackendT,
    output: &'a mut [u8],
    input: &[u8],
) -> Result<(StatusCode, &'a [u8]), Error<BackendT::Error>>
where
    BackendT: Backend,
    BackendT::Error: crate::std::fmt::Debug,
{
    #[cfg(feature = "tracing")]
    tracing::trace!(
        direction = "request",
        method = "plain",
        data = hex::encode(input)
    );

    let (status_code, response) = plain_multi(backend, output, input, &[]).await?;

    #[cfg(feature = "tracing")]
    tracing::trace!(
        direction = "response",
        method = "plain",
        status_code = format!("{:?}", status_code),
        data = hex::encode(response),
    );

    Ok((status_code, response))
}

/// Exchange a plain message with the underlying backend. This is how we
/// communicate with a card when there's no shared keying.
///
/// If the reply is for more data, we will continue to ask for data
/// until we see the end of the data. If this is not desired, you may
/// need to interact with the [Backend] directly.
pub async fn plain_multi<'a, BackendT>(
    backend: &BackendT,
    output: &'a mut [u8],
    header: &[u8],
    data: &[&[u8]],
) -> Result<(StatusCode, &'a [u8]), Error<BackendT::Error>>
where
    BackendT: Backend,
    BackendT::Error: crate::std::fmt::Debug,
{
    let (mut data, _data_len) = {
        let data_len = data.iter().fold(0, |n, data| n + data.len());
        (data.iter().flat_map(|v| v.iter()), data_len)
    };

    let mut command = header;
    let mut buf_in = [0; 0xff]; // used to create a command
    let mut buf_out = [0; 0xff]; // used to write responses to
    let mut n = 0;

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
                    .take(MAX_SIZE)
                    .copied()
                    .copy_to_slice(&mut buf_in[1..])
                {
                    // if we have more "outgoing" data, we need to pipe that
                    // out along with the 0xAF
                    command = &buf_in[..(n + 1)];
                } else {
                    command = &buf_in[..1];
                }
                continue;
            }
            _ => {
                return Ok((status_code, &output[..n]));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::MockBackend;
    use super::*;

    #[tokio::test]
    async fn test_plain() {
        let mb = MockBackend::new(&[(&[0xFF], b"\xAFHello, "), (&[0xAF], b"\x00World!")]);
        let mut out = [0; 0xff];
        let (status_code, response) = plain(&mb, &mut out, &[0xFF]).await.unwrap();
        assert_eq!(StatusCode::Ack, status_code);
        assert_eq!(b"Hello, World!", &response);
    }
}

// vim: foldmethod=marker
