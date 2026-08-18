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
    AppPermissions, DetailedVersionInfo, Key, KeyCount, KeyPermissions, Permissions, VersionInfo,
};

replay!(metadata, "metadata.replay", |card| {
    let mut out = [0; 0xffff];

    let mut card = card
        .authenticate_with_rnd_a(
            0x00,
            Key::Des([0; 8]),
            Key::Des(hex_literal::hex!("32 c2 8f da fd 39 60 de")),
        )
        .await
        .unwrap();

    let (permissions, key_count) = card.get_key_settings().await.unwrap();
    assert_eq!(
        Permissions {
            app: AppPermissions {
                anyone_can_delete: true,
                anyone_can_list: true,
                can_change_key_settings: true,
                can_change_root_key: true,
            },
            key: KeyPermissions::RequiresRoot,
        },
        permissions,
    );

    assert_eq!(KeyCount::Des(1), key_count);
    assert_eq!(0, card.get_key_version(0x00).await.unwrap());
    assert_eq!(0, card.list_applications(&mut out).await.unwrap().len());

    assert_eq!(
        hex_literal::hex!("04 64 d5 9a dd 1e 90"),
        card.get_uid().await.unwrap()
    );

    assert_eq!(
        VersionInfo {
            hardware: DetailedVersionInfo {
                vendor_id: 4,
                r#type: 1,
                sub_type: 1,
                major_version: 51,
                minor_version: 0,
                storage_size: 24,
                protocol_type: 5
            },
            software: DetailedVersionInfo {
                vendor_id: 4,
                r#type: 1,
                sub_type: 1,
                major_version: 3,
                minor_version: 0,
                storage_size: 24,
                protocol_type: 5
            },
            uid: [4, 100, 213, 154, 221, 30, 144],
            production_batch_number: [33, 19, 98, 48, 48],
            production_calendar_week: 64,
            production_year: 36
        },
        card.get_version_info().await.unwrap()
    );
});

// vim: foldmethod=marker
