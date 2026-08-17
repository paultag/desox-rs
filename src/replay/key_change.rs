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

replay!(
    key_change_app_des_des,
    "key_change_app_des_des.replay",
    |card| {
        let mut card = card
            .authenticate_with_rnd_a(
                0x00,
                Key::Des([0; 8]),
                Key::Des(hex_literal::hex!("C0 FF EE D0  0D 00 00 00")),
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
        let key_count = KeyCount::Des(1);

        card.create_application([1, 2, 3], key_settings, key_count)
            .await
            .unwrap();

        let card = card.select_application([1, 2, 3]).await.unwrap();
        let card = card
            .authenticate_with_rnd_a(
                0x00,
                Key::Des([0; 8]),
                Key::Des(hex_literal::hex!("C0 FF EE D0  0D 00 00 01")),
            )
            .await
            .unwrap();

        let card = card.change_current_key(Key::Des([2; 8]), 0).await.unwrap();

        let _card = card
            .authenticate_with_rnd_a(
                0x00,
                Key::Des([2; 8]),
                Key::Des(hex_literal::hex!("C0 FF EE D0  0D 00 00 02")),
            )
            .await
            .unwrap();
    }
);

replay!(
    key_change_app_aes_aes,
    "key_change_app_aes_aes.replay",
    |card| {
        let mut card = card
            .authenticate_with_rnd_a(
                0x00,
                Key::Des([0; 8]),
                Key::Des(hex_literal::hex!("C0 FF EE D0  0D 00 00 00")),
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
        let card = card
            .authenticate_with_rnd_a(
                0x00,
                Key::Aes([0; 16]),
                Key::Aes(hex_literal::hex!("C0FFEE BADCAB1E F00D F00D F00D F00D 01")),
            )
            .await
            .unwrap();

        let card = card.change_current_key(Key::Aes([2; 16]), 0).await.unwrap();

        let _card = card
            .authenticate_with_rnd_a(
                0x00,
                Key::Aes([2; 16]),
                Key::Aes(hex_literal::hex!("C0FFEE BADCAB1E F00D F00D F00D F00D 02")),
            )
            .await
            .unwrap();
    }
);

replay!(
    key_change_picc_round_the_world,
    "key_change_picc_round_the_world.replay",
    |card| {
        // DES default -> 2
        let card = card
            .authenticate_with_rnd_a(0x00, Key::Des([0; 8]), Key::Des([1; 8]))
            .await
            .unwrap()
            .change_current_key(Key::Des([2; 8]), 0)
            .await
            .unwrap();

        // DES 2 -> AES default
        let card = card
            .authenticate_with_rnd_a(0x00, Key::Des([2; 8]), Key::Des([2; 8]))
            .await
            .unwrap()
            .change_current_key(Key::Aes([0; 16]), 0)
            .await
            .unwrap();

        // AES default -> AES 1
        let card = card
            .authenticate_with_rnd_a(0x00, Key::Aes([0; 16]), Key::Aes([3; 16]))
            .await
            .unwrap()
            .change_current_key(Key::Aes([1; 16]), 0)
            .await
            .unwrap();

        // AES 1 -> DES default
        let card = card
            .authenticate_with_rnd_a(0x00, Key::Aes([1; 16]), Key::Aes([4; 16]))
            .await
            .unwrap()
            .change_current_key(Key::Des([0; 8]), 0)
            .await
            .unwrap();
    }
);

// vim: foldmethod=marker
