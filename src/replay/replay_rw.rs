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

// assert pcsc feature here too

macro_rules! replay {
    ($name:ident, $path:literal, |$card:ident| $body:tt) => {
        #[tokio::test]
        async fn $name() {
            use std::io::Write;

            // write transcript to $path

            let mut buf_reader_names = [0; 0xffff];
            let reader = "HID";
            let ctx = pcsc::Context::establish(pcsc::Scope::User).unwrap();
            let Some(name) = ctx
                .list_readers(&mut buf_reader_names)
                .unwrap()
                .find(|v| (*v).to_str().unwrap().contains(&reader))
            else {
                panic!("No reader found");
            };

            let card = ctx
                .connect(name, pcsc::ShareMode::Exclusive, pcsc::Protocols::RAW)
                .unwrap();

            let backend = $crate::io::TapBackend::new(&card);
            let $card = $crate::Card::new(&backend);
            $body;

            let mut f =
                std::fs::File::create(std::path::PathBuf::from("src/replay").join($path)).unwrap();
            for (tx, rx) in backend.into_inner() {
                f.write_all(format!("{} {}\n", hex::encode(tx), hex::encode(rx)).as_bytes())
                    .unwrap();
            }
        }
    };
}
pub(crate) use replay;

// vim: foldmethod=marker
