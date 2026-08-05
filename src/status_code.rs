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

macro_rules! status_codes {
    ( $( $name:ident = $code:literal - ($doc:expr) ),* ) => {
        /// Commands we can ask the card for
        #[derive(Copy, Clone, Debug, PartialEq)]
        pub enum StatusCode {
            /// Unknown status code
            Other(u8),

            $(
                #[doc = $doc]
                $name
            ),*
        }

        impl StatusCode {
            /// Convert the [StatusCode] into a u8
            pub fn as_u8(&self) -> u8 {
                match self {
                    Self::Other(code) => *code,
                    $( Self::$name => $code ),*
                }
            }

            /// Convert a u8 into a [StatusCode].
            pub fn from_u8(v: u8) -> Self {
                match v {
                    $( $code => Self::$name, )*
                    _ => Self::Other(v)
                }
            }
        }
    };
}

impl From<u8> for StatusCode {
    fn from(u: u8) -> Self {
        Self::from_u8(u)
    }
}

impl From<StatusCode> for u8 {
    fn from(sc: StatusCode) -> Self {
        sc.as_u8()
    }
}

status_codes!(
    Ack = 0x00 - ("Everything's OK!"),
    NoChanges = 0x0C - ("No changes"),
    OutOfMemory = 0x0E - ("Out of memory"),
    IllegalCommand = 0x1C - ("Illegal Command"),
    IntegrityError = 0x1E - ("Integrity error"),
    KeyDoesNotExist = 0x40 - ("Key does not exist"),
    WrongCommandLength = 0x7E - ("Wrong command length"),
    PermissionDenied = 0x9D - ("Permission denied"),
    IncorrectArguments = 0x9E - ("Incorrect command arguments"),
    ApplicationDoesNotExist = 0xA0 - ("Application does not exist"),
    ApplicationIntegrityError = 0xA1 - ("Application integrity error"),
    AuthenticationError = 0xAE - ("Authentication error"),
    AdditionalData = 0xAF - ("Additional Data"),
    LimitExceeded = 0xBE - ("Limit exceeded"),
    CardIntegrityError = 0xC1 - ("Card integrity error"),
    CommandAborted = 0xCA - ("Command aborted"),
    CardDisabled = 0xCD - ("Card disabled"),
    InvalidApplication = 0xCE - ("Invalid application"),
    DuplicateApplication = 0xDE - ("Duplicate application"),
    EepromError = 0xEE - ("EEPROM error"),
    FileNotFound = 0xF0 - ("File not found"),
    FileIntegrityError = 0xF1 - ("File integrity error")
);

// vim: foldmethod=marker
