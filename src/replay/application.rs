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
use crate::{AppPermissions, Key, KeyCount, KeyPermissions, Permissions};

replay!(application, "application.replay", |card| {
    let mut out = [0; 0xffff];

    let mut card = card
        .authenticate_with_rnd_a(
            0x00,
            Key::Des([0; 8]),
            Key::Des(hex_literal::hex!("32 c2 8f da fd 39 60 de")),
        )
        .await
        .unwrap();

    let key_settings = Permissions {
        app: AppPermissions {
            can_change_key_settings: true,
            can_change_picc_key: true,
            anyone_can_delete: false,
            anyone_can_list: false,
        },
        key: KeyPermissions::RequiresPicc,
    };
    let key_count = KeyCount::Aes(1);

    card.create_application([1, 2, 3], key_settings, key_count)
        .await
        .unwrap();

    let card = card.select_application([1, 2, 3]).await.unwrap();
    let mut card = card
        .authenticate_with_rnd_a(0x00, Key::Aes([0; 16]), Key::Aes([1; 16]))
        .await
        .unwrap();

    let (permissions, key_count) = card.get_key_settings().await.unwrap();

    assert_eq!(
        Permissions {
            app: AppPermissions {
                can_change_key_settings: true,
                can_change_picc_key: true,
                anyone_can_delete: false,
                anyone_can_list: false
            },
            key: KeyPermissions::RequiresPicc
        },
        permissions
    );
    assert_eq!(KeyCount::Aes(1), key_count);
    assert_eq!(0, card.get_key_version(0x00).await.unwrap());
    assert_eq!(0, card.list_files(&mut out).await.unwrap().len());

    let card = card.select_application([0, 0, 0]).await.unwrap();
    let mut card = card
        .authenticate_with_rnd_a(
            0x00,
            Key::Des([0; 8]),
            Key::Des(hex_literal::hex!("32 c2 8f da fd 39 60 de")),
        )
        .await
        .unwrap();
    card.delete_application([1, 2, 3]).await.unwrap();
});

// vim: foldmethod=marker
