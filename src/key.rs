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

/// MIFARE DESFire keys are symmetric keys that are shared by the reader
/// and the card. These can take the form of a few different algorithms,
/// but I have chosen to only support two for now -- DES and AES. DES is only
/// used for legacy interop (and default key authentication) -- if one of the
/// new flavors is to be used, I'm only using AES. Things like 3DES are not
/// something I've implemented (yet?).
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Key {
    /// 8-byte DES key (this is legacy).
    Des([u8; 8]),

    /// 16-byte AES key (this is the one that you generally want to use).
    Aes([u8; 16]),
}

// vim: foldmethod=marker
