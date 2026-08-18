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

mod application;
mod file_io;
mod key_change;
mod metadata;
#[cfg(not(desox_replay_rw))]
mod replay;
#[cfg(desox_replay_rw)]
mod replay_rw;

#[cfg(not(desox_replay_rw))]
fn parse_replay(lines: &'static str) -> Vec<(Vec<u8>, Vec<u8>)> {
    lines
        .lines()
        .map(|v| {
            let [tx, rx] = v
                .splitn(2, ' ')
                .map(|v| hex::decode(v).unwrap())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            (tx, rx)
        })
        .collect()
}

#[cfg(not(desox_replay_rw))]
pub(crate) use replay::replay;

#[cfg(desox_replay_rw)]
pub(crate) use replay_rw::replay;

// vim: foldmethod=marker
