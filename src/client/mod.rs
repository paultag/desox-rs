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

//! "raw" DESFire client code. This is a fairly direct one-to-one client
//! wrapper which is (hopefully) useful on its own, yet likely just a little
//! more low-level than most people actually want. This is here to be an
//! "escape hatch" when higher-level bindings are not quite cutting it.

mod card;
mod card_authenticated;
mod card_default;
mod card_unauthenticated;
mod cmd_applications;
mod cmd_authenticate;
mod cmd_card_version;
mod cmd_file;
mod cmd_format_card;
mod cmd_key;
mod cmd_real_uid;
mod handshake;
mod keying;
mod session;

pub use card::{AuthenticationState, Card};
pub use card_authenticated::Authenticated;
pub use card_unauthenticated::Unauthenticated;
pub use cmd_file::FileIo;
pub use keying::KeyingState;
pub use session::Session;

use card::{
    command, command_cmac, command_encrypted_request, command_encrypted_response, command_header,
};
use card_default::CardIoDefault;
pub(crate) use handshake::AuthenticateExt;

/// Type alias for a card which is currently unauthenticated.
pub type UnauthenticatedCard<'card, IoBackend> = Card<'card, IoBackend, Unauthenticated>;

/// Type alias for a card which is currently authenticated.
pub type AuthenticatedCard<'card, IoBackend> = Card<'card, IoBackend, Authenticated>;

// vim: foldmethod=marker
