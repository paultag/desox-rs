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

/// Helper-trait to allow for copying an iterator of type 'T' to a mutable
/// iterator of type 'T'.
pub(crate) trait CopyToSlice<T>
where
    Self: Iterator<Item = T>,
{
    /// Copy 'T' from the underlying iterator to the mutable array of type 'T'
    /// returning the number of elements written to the output slice.
    fn copy_to_slice(&mut self, out: &mut [T]) -> Option<usize>;
}

impl<T, IterT> CopyToSlice<T> for IterT
where
    IterT: Iterator<Item = T>,
    T: Copy,
{
    fn copy_to_slice(&mut self, out: &mut [T]) -> Option<usize> {
        let n = self.zip(out.iter_mut()).fold(0, |n, (input, output)| {
            *output = input;
            n + 1
        });
        if n == 0 {
            return None;
        }
        Some(n)
    }
}

// vim: foldmethod=marker
