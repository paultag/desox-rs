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

use crate::{Error, KeyId};

/// Global (PICC-wide) and Application-specific configuration surrounding
/// permissions regarding keying material.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct KeySettings {
    /// Key Settings specific to the PICC Key.
    pub picc: KeySettingsPicc,

    /// Key Settings specific to the Application Key(s).
    pub app: KeySettingsApp,
}

impl KeySettings {
    /// Default default application MIFARE DESFire EV3 key settings (0x0F)
    pub const FACTORY_DEFAULT: Self = Self {
        picc: KeySettingsPicc {
            can_change_key_settings: true,
            can_change_picc_key: true,
            anyone_can_delete: true,
            anyone_can_list: true,
        },
        app: KeySettingsApp::RequiresPicc,
    };
}

/// PICC-wide Key Settings. This represents what permissions are required
/// to take card-wide destructive actions, such as creating or deleting
/// applications, changing key permissions, or changing the PICC key.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct KeySettingsPicc {
    /// If true, the key settings (like, this very configuration!) can be
    /// changed. If false, these settings are locked in forever.
    pub can_change_key_settings: bool,

    /// If true, the PICC key ("master key", or key 0x00 in the default
    /// application (00 00 00)) can be changed. If false, the PICC key may
    /// not be changed.
    pub can_change_picc_key: bool,

    /// If true, deleting applications does not require authentication
    /// with the PICC key ("master key").
    pub anyone_can_delete: bool,

    /// If true, listing applications does not require authentication
    /// with the PICC key ("master key").
    pub anyone_can_list: bool,
}

impl KeySettingsPicc {
    const CAN_CHANGE_PICC_KEY: u8 = 0x01;
    const ANYONE_CAN_LIST: u8 = 0x02;
    const ANYONE_CAN_DELETE: u8 = 0x04;
    const CAN_CHANGE_KEY_SETTINGS: u8 = 0x08;

    /// Create a new [KeySettingsPicc] from the provided [KeySettings] encoded
    /// value.
    fn from_u8(ks: u8) -> Self {
        Self {
            can_change_picc_key: (ks & Self::CAN_CHANGE_PICC_KEY) != 0,
            anyone_can_list: (ks & Self::ANYONE_CAN_LIST) != 0,
            anyone_can_delete: (ks & Self::ANYONE_CAN_DELETE) != 0,
            can_change_key_settings: (ks & Self::CAN_CHANGE_KEY_SETTINGS) != 0,
        }
    }

    /// Create a new [KeySettings] encoded value.
    pub fn as_u8(&self) -> u8 {
        (if self.can_change_picc_key {
            Self::CAN_CHANGE_PICC_KEY
        } else {
            0
        }) | (if self.anyone_can_list {
            Self::ANYONE_CAN_LIST
        } else {
            0
        }) | (if self.anyone_can_delete {
            Self::ANYONE_CAN_DELETE
        } else {
            0
        }) | (if self.can_change_key_settings {
            Self::CAN_CHANGE_KEY_SETTINGS
        } else {
            0
        })
    }
}

/// Application-specific Key settings. This defines what key is required to
/// be used when taking specific keying actions.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum KeySettingsApp {
    /// Changing an Application key requires authentication with
    /// the PICC Key ("master key").
    RequiresPicc,

    /// Changing an Application key requires authentication with the
    /// provided Application key (must be within the range of 1 to 13,
    /// 13 inclusive).
    RequiresAppKey(KeyId),

    /// Changing an Application key requires authentication with the
    /// key to be changed itself.
    RequiresTargetedAppKey,

    /// Application keys may not be changed.
    Frozen,
}

impl KeySettingsApp {
    /// Create a new [KeySettingsApp] from the provided [KeySettings] encoded
    /// value.
    fn from_u8(ks: u8) -> Self {
        match ks >> 4 {
            0x00 => Self::RequiresPicc,
            0x0E => Self::RequiresTargetedAppKey,
            0x0F => Self::Frozen,
            ks => Self::RequiresAppKey(ks),
        }
    }

    /// Create a new [KeySettings] encoded value.
    ///
    /// 'IoBackendErrorT' is generic here because [Error] requires it, this
    /// function does not conduct any I/O on its own. We will never return an
    /// [Error::IoBackend], so this is purely for sizing/checking.
    fn as_u8<IoBackendErrorT>(&self) -> Result<u8, Error<IoBackendErrorT>> {
        Ok((match &self {
            Self::RequiresPicc => 0x00,
            Self::RequiresAppKey(key @ 0x01..=0x0D) => *key,
            Self::RequiresAppKey(_) => return Err(Error::BadKeyId),
            Self::RequiresTargetedAppKey => 0x0E,
            Self::Frozen => 0x0F,
        }) << 4)
    }
}

impl KeySettings {
    /// Create a new [KeySettings] from the provided [KeySettings] encoded
    /// value.
    pub fn from_u8(ks: u8) -> Self {
        Self {
            picc: KeySettingsPicc::from_u8(ks),
            app: KeySettingsApp::from_u8(ks),
        }
    }

    /// Create a new [KeySettings] encoded value.
    ///
    /// 'IoBackendErrorT' is generic here because [Error] requires it, this
    /// function does not conduct any I/O on its own. We will never return an
    /// [Error::IoBackend], so this is purely for sizing/checking.
    pub fn as_u8<IoBackendErrorT>(&self) -> Result<u8, Error<IoBackendErrorT>> {
        Ok(self.picc.as_u8() | self.app.as_u8()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_settings_round_trips() {
        for key_settings in 0..0xff {
            let key_settings_parsed = KeySettings::from_u8(key_settings);
            let key_settings_rt = key_settings_parsed.as_u8::<()>().unwrap();
            assert_eq!(key_settings, key_settings_rt);
        }
    }

    macro_rules! test_key_settings {
        ($name:ident { $settings:expr, $key_settings:expr }) => {
            #[test]
            fn $name() {
                let key_settings = KeySettings::from_u8($settings);
                assert_eq!($key_settings, key_settings);
                let key_settings_u8 = key_settings.as_u8::<()>().unwrap();
                assert_eq!($settings, key_settings_u8);
            }
        };
    }

    test_key_settings!(test_factory_default { 0x0F, KeySettings::FACTORY_DEFAULT });

    test_key_settings!(test_app_frozen { 0x00, KeySettings {
        picc: KeySettingsPicc {
            can_change_key_settings: false,
            can_change_picc_key: false,
            anyone_can_delete: false,
            anyone_can_list: false,
        },
        app: KeySettingsApp::RequiresPicc,
    } });

    test_key_settings!(test_app_a { 0xAF, KeySettings {
        picc: KeySettingsPicc {
            can_change_key_settings: true,
            can_change_picc_key: true,
            anyone_can_delete: true,
            anyone_can_list: true,
        },
        app: KeySettingsApp::RequiresAppKey(10),
    } });

    macro_rules! test_bad_key_settings {
        ($name:ident { $key_settings:expr }) => {
            #[test]
            fn $name() {
                assert!($key_settings.as_u8::<()>().is_err());
            }
        };
    }

    test_bad_key_settings!(test_bad_app_0 { KeySettings {
        picc: KeySettingsPicc {
            can_change_key_settings: true,
            can_change_picc_key: true,
            anyone_can_delete: true,
            anyone_can_list: true,
        },
        app: KeySettingsApp::RequiresAppKey(0),
    } });

    test_bad_key_settings!(test_bad_app_e { KeySettings {
        picc: KeySettingsPicc {
            can_change_key_settings: true,
            can_change_picc_key: true,
            anyone_can_delete: true,
            anyone_can_list: true,
        },
        app: KeySettingsApp::RequiresAppKey(0xE),
    } });
}

// vim: foldmethod=marker
