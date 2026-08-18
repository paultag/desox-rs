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

use crate::{ApplicationId, io};

/// Create a new struct for this command with an in-memory layout such that we
/// can do tragically unsafe things with the resulting payload.
macro_rules! command {
    ($slf:expr, $out:expr, { $( $field_name:ident: $field_type:ty = $field_value:expr ),* }, $size:literal, [ $( $body:expr ),* ]) => {{
        let header: [u8; $size] = $crate::client::command_header!({
            $( $field_name: $field_type = $field_value ),*
        }, $size);
        $slf.default_exchange_multi($out, &header, &[ $( $body ),* ]).await?
    }};
}
pub(super) use command;

/// Do what [command] does, but use the card-mini buffer.
macro_rules! command_de_minimis {
    ($slf:expr, { $( $field_name:ident: $field_type:ty = $field_value:expr ),* }, $size:literal, [ $( $body:expr ),* ]) => {{
        let header: [u8; $size] = $crate::client::command_header!({
            $( $field_name: $field_type = $field_value ),*
        }, $size);
        $slf.default_exchange_multi_de_minimis(&header, &[ $( $body ),* ]).await?
    }};
}
pub(super) use command_de_minimis;

macro_rules! command_cmac_de_minimis {
    ($slf:expr, { $( $field_name:ident: $field_type:ty = $field_value:expr ),* }, $size:literal, [ $( $body:expr ),* ]) => {{
        let header: [u8; $size] = $crate::client::command_header!({
            $( $field_name: $field_type = $field_value ),*
        }, $size);

        match &mut $slf.authentication.session {
            $crate::client::Session::Aes { keying, .. } => {
                $crate::io::cmac_out_cmac_in(&$slf.card, keying, &mut $slf.buf, &header, &[ $( $body ),* ]).await?
            },
            $crate::client::Session::Des { keying, .. } => {
                $crate::io::cmac_out_cmac_in(&$slf.card, keying, &mut $slf.buf, &header, &[ $( $body ),* ]).await?
            },
        }
    }};
}
pub(super) use command_cmac_de_minimis;

macro_rules! command_encrypted_request_de_minimis {
    ($slf:expr, { $( $field_name:ident: $field_type:ty = $field_value:expr ),* }, $size:literal, [ $( $body:expr ),* ]) => {{
        let header: [u8; $size] = $crate::client::command_header!({
            $( $field_name: $field_type = $field_value ),*
        }, $size);

        let crc = $crate::crc32(&header, &[ $( $body ),* ]).to_le_bytes();
        match &mut $slf.authentication.session {
            $crate::client::Session::Aes { keying, .. } => {
                $crate::io::encrypted_out_cmac_in(&$slf.card, keying, &mut $slf.buf, &header, &[ $( $body, )* &crc ]).await?
            },
            $crate::client::Session::Des { keying, .. } => {
                $crate::io::encrypted_out_cmac_in(&$slf.card, keying, &mut $slf.buf, &header, &[ $( $body, )* &crc ]).await?
            },
        }
    }};
}
pub(super) use command_encrypted_request_de_minimis;

macro_rules! command_encrypted_response {
    ($slf:expr, $out:expr, { $( $field_name:ident: $field_type:ty = $field_value:expr ),* }, $size:literal, [ $( $body:expr ),* ]) => {{
        let header: [u8; $size] = $crate::client::command_header!({
            $( $field_name: $field_type = $field_value ),*
        }, $size);

        match &mut $slf.authentication.session {
            $crate::client::Session::Aes { keying, .. } => {
                $crate::io::plain_out_encrypted_in(&$slf.card, keying, $out, &header, &[ $( $body ),* ]).await?
            },
            $crate::client::Session::Des { keying, .. } => {
                $crate::io::plain_out_encrypted_in(&$slf.card, keying, $out, &header, &[ $( $body ),* ]).await?
            },
        }
    }};
}
pub(super) use command_encrypted_response;

macro_rules! command_encrypted_response_de_minimis {
    ($slf:expr, { $( $field_name:ident: $field_type:ty = $field_value:expr ),* }, $size:literal, [ $( $body:expr ),* ]) => {{
        let header: [u8; $size] = $crate::client::command_header!({
            $( $field_name: $field_type = $field_value ),*
        }, $size);

        match &mut $slf.authentication.session {
            $crate::client::Session::Aes { keying, .. } => {
                $crate::io::plain_out_encrypted_in(&$slf.card, keying, &mut $slf.buf, &header, &[ $( $body ),* ]).await?
            },
            $crate::client::Session::Des { keying, .. } => {
                $crate::io::plain_out_encrypted_in(&$slf.card, keying, &mut $slf.buf, &header, &[ $( $body ),* ]).await?
            },
        }
    }};
}
pub(super) use command_encrypted_response_de_minimis;

macro_rules! command_header {
    ({ $( $field_name:ident: $field_type:ty = $field_value:expr ),* }, $size:literal) => {{
        #[repr(C, packed)]
        #[allow(dead_code)]
        #[derive(Debug)]
        struct Command {
            $( $field_name: $field_type ),*
        }

        let header = Command {
            $( $field_name: $field_value ),*
        };

        #[allow(unsafe_code)]
        unsafe { $crate::std::mem::transmute::<Command, [u8; $size]>(header) }
    }};
}
pub(super) use command_header;

/// Valid authentication state, with default(s) on how to handle communication
/// with the card. This trait is here to limit possible states but is not
/// generally useful.
pub trait AuthenticationState {}

/// Handle to interact with a MiFare DESFire card.
pub struct Card<'card, IoBackendT, AuthenticationStateT>
where
    AuthenticationStateT: AuthenticationState,
    IoBackendT: io::Backend,
{
    /// The "de minimis" buffer. This is used when we're expecting a
    /// 'de minimis' amount of pro-forma (trying to use as much of the
    /// same jargon as possible here) data back -- like a status code and
    /// a CMAC signature.
    ///
    /// If the read data is something like file contents, we don't want to
    /// be using this buffer.
    pub(super) buf: [u8; 60],

    pub(super) application_id: ApplicationId,
    pub(super) card: &'card IoBackendT,
    pub(super) authentication: AuthenticationStateT,
}

impl<'card, AuthenticationStateT, IoBackendT> AsRef<IoBackendT>
    for Card<'card, IoBackendT, AuthenticationStateT>
where
    AuthenticationStateT: AuthenticationState,
    IoBackendT: io::Backend,
{
    fn as_ref(&self) -> &IoBackendT {
        self.card
    }
}

impl<'card, AuthenticationStateT, IoBackendT> Card<'card, IoBackendT, AuthenticationStateT>
where
    AuthenticationStateT: AuthenticationState,
    IoBackendT: io::Backend,
{
    /// Return a ref to the inner authentication state.
    pub fn authentication_state(&self) -> &AuthenticationStateT {
        &self.authentication
    }
}

// vim: foldmethod=marker
