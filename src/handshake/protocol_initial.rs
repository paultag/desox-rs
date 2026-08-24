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

use super::{HalfOpen, Handshake, Initiate};
use crate::{
    Error, Instruction,
    crypto::{Backend, Scheme},
};

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Initial;

impl<const KEY_SIZE: usize, AlgorithmT> Handshake<KEY_SIZE, AlgorithmT, Initial>
where
    Scheme<KEY_SIZE, AlgorithmT>: Backend<KEY_SIZE>,
    Scheme<KEY_SIZE, AlgorithmT>: Initiate,
{
    /// Begin the authentication flow
    pub fn begin(output: &mut [u8], key: [u8; KEY_SIZE], key_id: u8) -> (Self, &[u8]) {
        output[0] = Scheme::<KEY_SIZE, AlgorithmT>::instruction() as u8;
        output[1] = key_id;
        let command = &output[..2];

        #[cfg(feature = "tracing")]
        tracing::trace!("authentication initiated");

        (
            Self {
                keying: Scheme::<KEY_SIZE, AlgorithmT>::new(key),
                state: Initial,
            },
            command,
        )
    }

    /// Given a new `RnbB` message from the chip, decode and compute
    /// a response to indicate our control of the same shared secret.
    ///
    /// This will generate a new (random) RndA to compute a shared
    /// secret.
    ///
    /// 'IoBackendTError' is generic here because [Error] requires it, this
    /// function does not conduct any I/O on its own. We will never return an
    /// [Error::IoBackend], so this is purely for sizing/checking.
    #[allow(clippy::type_complexity)]
    pub fn rnd_b<'a, IoBackendErrorT>(
        self,
        output: &'a mut [u8],
        input: &[u8],
    ) -> Result<
        (
            Handshake<KEY_SIZE, AlgorithmT, HalfOpen<KEY_SIZE>>,
            &'a [u8],
        ),
        Error<IoBackendErrorT>,
    > {
        let mut rnd_a = [0u8; KEY_SIZE];
        getrandom::fill(&mut rnd_a).map_err(Error::Getrandom)?;
        self.rnd_b_with_key(output, input, rnd_a)
    }

    /// Given a new `RnbB` message from the chip, decode and compute
    /// a response to indicate our control of the same shared secret.
    ///
    /// This will use the provided RnbA
    ///
    /// 'IoBackendTError' is generic here because [Error] requires it, this
    /// function does not conduct any I/O on its own. We will never return an
    /// [Error::IoBackend], so this is purely for sizing/checking.
    #[allow(clippy::type_complexity)]
    pub fn rnd_b_with_key<'a, IoBackendErrorT>(
        self,
        output: &'a mut [u8],
        input: &[u8],
        rnd_a: [u8; KEY_SIZE],
    ) -> Result<
        (
            Handshake<KEY_SIZE, AlgorithmT, HalfOpen<KEY_SIZE>>,
            &'a [u8],
        ),
        Error<IoBackendErrorT>,
    > {
        let Self {
            mut keying,
            state: _,
        } = self;

        if input.len() != KEY_SIZE {
            return Err(Error::BadSize);
        }

        // Decrypt RndB to `buf`, and convert it into a [u8; KEY_SIZE]
        // (copying it out of `buf`).

        let rnd_b = {
            let mut rnd_b = input.to_vec();
            keying.decrypt(&mut rnd_b);
            let rnd_b: [u8; KEY_SIZE] = rnd_b.try_into().unwrap();
            rnd_b
        };

        #[cfg(feature = "insecure-trace-private-keys")]
        tracing::trace!(
            rnd_a = hex::encode(rnd_a),
            rnd_b = hex::encode(rnd_b),
            "RndB challange, half-open"
        );

        let command = &mut output[..(KEY_SIZE * 2) + 1];
        command[0] = Instruction::AdditionalData as u8;
        {
            let command = &mut command[1..];
            assert_eq!(KEY_SIZE * 2, command.len());

            let mut n = 0;
            command[n..(n + KEY_SIZE)].copy_from_slice(&rnd_a);
            n += KEY_SIZE;
            command[n..(n + KEY_SIZE)].copy_from_slice(&rnd_b);
            command[n..(n + KEY_SIZE)].rotate_left(1);
            keying.encrypt(command);
        }

        let handshake = Handshake {
            keying,
            state: HalfOpen { rnd_a, rnd_b },
        };

        Ok((handshake, command))
    }
}

// vim: foldmethod=marker
