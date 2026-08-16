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

use super::replay;
use crate::{
    FileCommunication, FileIo, FilePermissions, FileSettings, FileType, Key, KeyCount, KeySettings,
    KeySettingsApp, KeySettingsPicc,
};

const TEST_STRING: &[u8] = b"\
Had I the heavens' embroidered cloths,
Enwrought with golden and silver light,
The blue and the dim and the dark cloths
Of night and light and the half light,
I would spread the cloths under your feet:
But I, being poor, have only my dreams;
I have spread my dreams under your feet;
Tread softly because you tread on my dreams.
";

replay!(file_io, "file_io.replay", |card| {
    let mut out = [0; 0xffff];

    let mut card = card
        .authenticate_with_rnd_a(
            0x00,
            Key::Des([0; 8]),
            Key::Des(hex_literal::hex!("32 c2 8f da fd 39 60 de")),
        )
        .await
        .unwrap();

    let key_settings = KeySettings {
        picc: KeySettingsPicc {
            can_change_key_settings: true,
            can_change_picc_key: true,
            anyone_can_delete: false,
            anyone_can_list: false,
        },
        app: KeySettingsApp::RequiresPicc,
    };
    let key_count = KeyCount::Aes(1);

    card.create_application([1, 2, 3], key_settings, key_count)
        .await
        .unwrap();

    let card = card.select_application([1, 2, 3]).await.unwrap();
    let mut card = card
        .authenticate_with_rnd_a(
            0x00,
            Key::Aes([0; 16]),
            Key::Aes(hex_literal::hex!(
                "c6 b7 81 42 8d 97 88 37 a6 36 08 99 11 9f 0d a4"
            )),
        )
        .await
        .unwrap();

    card.create_file(
        0x01,
        FileSettings {
            type_: FileType::Data,
            communication: FileCommunication::Plain,
            permissions: FilePermissions {
                change: 0x00,
                read_write: 0x00,
                write: 0x00,
                read: 0x00,
            },
            size: TEST_STRING.len() as u32,
        },
    )
    .await
    .unwrap();

    card.create_file(
        0x02,
        FileSettings {
            type_: FileType::Data,
            communication: FileCommunication::Cmac,
            permissions: FilePermissions {
                change: 0x00,
                read_write: 0x00,
                write: 0x00,
                read: 0x00,
            },
            size: TEST_STRING.len() as u32,
        },
    )
    .await
    .unwrap();

    card.create_file(
        0x03,
        FileSettings {
            type_: FileType::Data,
            communication: FileCommunication::Encrypted,
            permissions: FilePermissions {
                change: 0x00,
                read_write: 0x00,
                write: 0x00,
                read: 0x00,
            },
            size: TEST_STRING.len() as u32,
        },
    )
    .await
    .unwrap();

    for fid in [0x01, 0x02, 0x03] {
        let file_settings = card.get_file_settings(fid).await.unwrap();

        card.write_file_at(fid, file_settings.communication, 0, TEST_STRING)
            .await
            .unwrap();

        card.read_file_at(
            &mut out,
            fid,
            file_settings.communication,
            0,
            file_settings.size,
        )
        .await
        .unwrap();
    }
});

// vim: foldmethod=marker
