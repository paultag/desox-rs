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

#![deny(missing_docs)]
#![deny(missing_copy_implementations)]
#![deny(trivial_casts)]
#![deny(trivial_numeric_casts)]
#![deny(unused_import_braces)]
#![deny(unused_qualifications)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![cfg_attr(not(any(test, feature = "std")), no_std)]

//! DESOx is a (very basic and partial!) implementaiton of the MIFARE DESFire
//! protocol. This protocol has a number of public implementations that I've
//! studied, but the actual documentation is under NDA, which I have not signed.
//!
//! This crate will (likely forever?) be partial, incomplete, and filled with
//! nasal demons -- but the only goal is to reliably do the "basics".

extern crate alloc;

mod client;
pub mod io;

mod copy_to_slice;
mod crc;
mod crypto;
mod error;
mod file;
mod instruction;
mod key;
mod key_count;
mod key_settings;
mod padding;
#[cfg(feature = "pcsc")]
mod pcsc;
#[cfg(test)]
mod replay;
mod status_code;
mod version_info;

pub use client::{
    Authenticated, AuthenticatedCard, AuthenticationState, Card, FileIo, KeyingState, Session,
    Unauthenticated, UnauthenticatedCard,
};
pub use error::Error;
pub use file::{FileCommunication, FilePermissions, FileSettings, FileType};
pub use instruction::Instruction;
pub use key::Key;
pub use key_count::KeyCount;
pub use key_settings::{KeySettings, KeySettingsApp, KeySettingsPicc};
pub use status_code::StatusCode;
pub use version_info::{DetailedVersionInfo, VersionInfo};

use copy_to_slice::CopyToSlice;
use crc::crc32;
use padding::Padding;

/// MIFARE DESFire Cards all have a Unique ID ([Uid]). UIDs are 7 bytes long,
/// and are generally only readable after authentication.
pub type Uid = [u8; 7];

/// MiFare DESFire Cards can have a number of "applications", identified by
/// an [ApplicationId]. These IDs are unique within a Card (or I guess more
/// specifically, a Card ecosystem), used to create a logical group of Files,
/// Keys and access control to serve the needs of the system.
pub type ApplicationId = [u8; 3];

/// MIFARE DESFire Cards have a number of key slot(s). The card itself - what
/// I usually call the PICC in this source ('Proximity Integrated Circuit Card')
/// has one PICC Key (their docs call it a 'Master Key') for card-wide
/// administrative actions, as well as a number (up to 15) Application Keys.
pub type KeyId = u8;

/// MIFARE DESFire Applications may contain "Files". A File may be of a given
/// type ('data', etc), from 0x00 to 0x1F (inclusive).
pub type FileId = u8;

pub(crate) mod std {
    pub use ::alloc::fmt;
    pub use ::alloc::vec;
    pub use ::core::convert;
    pub use ::core::future;
    pub use ::core::marker;
    pub use ::core::mem;
    pub use ::core::ops;
    pub use ::core::sync;
}

// vim: foldmethod=marker
