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

/// Global (PICC-wide) and Application-specific permissions and
/// configuration.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Permissions {
    /// Permissions regarding what operations can be done in what
    /// state(s).
    pub app: AppPermissions,

    /// Permissions regarding key changes (specifically) within the current
    /// Application.
    pub key: KeyPermissions,
}

impl Permissions {
    /// Default default application MIFARE DESFire EV3 key settings (0x0F)
    pub const FACTORY_DEFAULT: Self = Self {
        app: AppPermissions {
            can_change_key_settings: true,
            can_change_root_key: true,
            anyone_can_delete: true,
            anyone_can_list: true,
        },
        key: KeyPermissions::RequiresRoot,
    };
}

/// Application-wide Key Settings. This represents what permissions are
/// required to take app-wide destructive actions, such as creating or deleting
/// applications, changing key permissions, or changing the root key.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct AppPermissions {
    /// If true, the key settings (like, this very configuration!) can be
    /// changed. If false, these settings are locked in forever.
    pub can_change_key_settings: bool,

    /// If true, the root key ("master key", or key 0x00 in the default
    /// application (00 00 00)) can be changed. If false, the root key may
    /// not be changed.
    pub can_change_root_key: bool,

    /// If true, deleting applications does not require authentication
    /// with the root key ("master key").
    pub anyone_can_delete: bool,

    /// If true, listing applications does not require authentication
    /// with the root key ("master key").
    pub anyone_can_list: bool,
}

impl AppPermissions {
    const CAN_CHANGE_ROOT_KEY: u8 = 0x01;
    const ANYONE_CAN_LIST: u8 = 0x02;
    const ANYONE_CAN_DELETE: u8 = 0x04;
    const CAN_CHANGE_KEY_SETTINGS: u8 = 0x08;

    /// Create a new [AppPermissions] from the provided [Permissions] encoded
    /// value.
    fn from_u8(ks: u8) -> Self {
        Self {
            can_change_root_key: (ks & Self::CAN_CHANGE_ROOT_KEY) != 0,
            anyone_can_list: (ks & Self::ANYONE_CAN_LIST) != 0,
            anyone_can_delete: (ks & Self::ANYONE_CAN_DELETE) != 0,
            can_change_key_settings: (ks & Self::CAN_CHANGE_KEY_SETTINGS) != 0,
        }
    }

    /// Create a new [Permissions] encoded value.
    pub fn as_u8(&self) -> u8 {
        (if self.can_change_root_key {
            Self::CAN_CHANGE_ROOT_KEY
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
pub enum KeyPermissions {
    /// Changing an Application key requires authentication with
    /// the Root Key ("master key").
    RequiresRoot,

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

impl KeyPermissions {
    /// Create a new [KeyPermissions] from the provided [Permissions] encoded
    /// value.
    fn from_u8(ks: u8) -> Self {
        match ks >> 4 {
            0x00 => Self::RequiresRoot,
            0x0E => Self::RequiresTargetedAppKey,
            0x0F => Self::Frozen,
            ks => Self::RequiresAppKey(ks),
        }
    }

    /// Create a new [Permissions] encoded value.
    ///
    /// 'IoBackendErrorT' is generic here because [Error] requires it, this
    /// function does not conduct any I/O on its own. We will never return an
    /// [Error::IoBackend], so this is purely for sizing/checking.
    fn as_u8<IoBackendErrorT>(&self) -> Result<u8, Error<IoBackendErrorT>> {
        Ok((match &self {
            Self::RequiresRoot => 0x00,
            Self::RequiresAppKey(key @ 0x01..=0x0D) => *key,
            Self::RequiresAppKey(_) => return Err(Error::BadKeyId),
            Self::RequiresTargetedAppKey => 0x0E,
            Self::Frozen => 0x0F,
        }) << 4)
    }
}

impl Permissions {
    /// Create a new [Permissions] from the provided [Permissions] encoded
    /// value.
    pub fn from_u8(ks: u8) -> Self {
        Self {
            app: AppPermissions::from_u8(ks),
            key: KeyPermissions::from_u8(ks),
        }
    }

    /// Create a new [Permissions] encoded value.
    ///
    /// 'IoBackendErrorT' is generic here because [Error] requires it, this
    /// function does not conduct any I/O on its own. We will never return an
    /// [Error::IoBackend], so this is purely for sizing/checking.
    pub fn as_u8<IoBackendErrorT>(&self) -> Result<u8, Error<IoBackendErrorT>> {
        Ok(self.app.as_u8() | self.key.as_u8()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_settings_round_trips() {
        for key_settings in 0..0xff {
            let key_settings_parsed = Permissions::from_u8(key_settings);
            let key_settings_rt = key_settings_parsed.as_u8::<()>().unwrap();
            assert_eq!(key_settings, key_settings_rt);
        }
    }

    macro_rules! test_key_settings {
        ($name:ident { $settings:expr, $key_settings:expr }) => {
            #[test]
            fn $name() {
                let key_settings = Permissions::from_u8($settings);
                assert_eq!($key_settings, key_settings);
                let key_settings_u8 = key_settings.as_u8::<()>().unwrap();
                assert_eq!($settings, key_settings_u8);
            }
        };
    }

    test_key_settings!(test_factory_default { 0x0F, Permissions::FACTORY_DEFAULT });

    test_key_settings!(test_app_frozen { 0x00, Permissions {
        app: AppPermissions {
            can_change_key_settings: false,
            can_change_root_key: false,
            anyone_can_delete: false,
            anyone_can_list: false,
        },
        key: KeyPermissions::RequiresRoot,
    } });

    test_key_settings!(test_app_a { 0xAF, Permissions {
        app: AppPermissions {
            can_change_key_settings: true,
            can_change_root_key: true,
            anyone_can_delete: true,
            anyone_can_list: true,
        },
        key: KeyPermissions::RequiresAppKey(10),
    } });

    macro_rules! test_bad_key_settings {
        ($name:ident { $key_settings:expr }) => {
            #[test]
            fn $name() {
                assert!($key_settings.as_u8::<()>().is_err());
            }
        };
    }

    test_bad_key_settings!(test_bad_app_0 { Permissions {
        app: AppPermissions {
            can_change_key_settings: true,
            can_change_root_key: true,
            anyone_can_delete: true,
            anyone_can_list: true,
        },
        key: KeyPermissions::RequiresAppKey(0),
    } });

    test_bad_key_settings!(test_bad_app_e { Permissions {
        app: AppPermissions {
            can_change_key_settings: true,
            can_change_root_key: true,
            anyone_can_delete: true,
            anyone_can_list: true,
        },
        key: KeyPermissions::RequiresAppKey(0xE),
    } });
}

// vim: foldmethod=marker
