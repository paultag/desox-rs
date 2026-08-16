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

pub trait U24 {
    fn to_le_bytes(self) -> [u8; 3];
    fn from_le_bytes(v: [u8; 3]) -> Self;
}

impl U24 for u32 {
    fn to_le_bytes(self) -> [u8; 3] {
        let size: [u8; 4] = u32::to_le_bytes(self);
        let size: [u8; 3] = [size[0], size[1], size[2]];
        size
    }

    fn from_le_bytes(v: [u8; 3]) -> Self {
        let [v1, v2, v3] = v;
        Self::from_le_bytes([v1, v2, v3, 0x00])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u32_io() {
        for i in 0..0xFFFFFFu32 {
            let tripplet = U24::to_le_bytes(i);
            let ii = U24::from_le_bytes(tripplet);
            assert_eq!(i, ii);
        }
    }
}

// vim: foldmethod=marker
