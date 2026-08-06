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

/// Errors that can be encountered when interacting with a MIFARE DESFire
/// card. This is fairly expansive (and has a generic for an error returned
/// by the specific I/O backend you're using).
#[derive(Debug, thiserror::Error)]
pub enum Error<IoBackendErrorT> {
    /// An error was returned by the underlying [crate::io::Backend].
    #[error("IO Backend returned an error")]
    IoBackend(IoBackendErrorT),

    /// DESFire Card replied with a bad or unexpected StatusCode
    #[error("DESFire Card replied with a bad or unexpected StatusCode")]
    BadStatusCode,

    /// The amount of data returned by the DESFire Card was wrong or unexpected.
    #[error("The amount of data returned by the DESFire Card was wrong or unexpected.")]
    BadSize,

    /// The Key ID is out of bounds -- there may only be a max of 15 keys.
    #[error("Key ID is out of bounds")]
    BadKeyId,

    /// The response from the Card is such that we do not share the same private
    /// key.
    #[error("Invalid Authentication challenge response")]
    InvalidHandshakeResponse,

    /// The signature from the card does not match our calculation of the
    /// card state.
    #[error("Invalid CMAC signature")]
    InvalidSignature,

    /// The crc32 checksum is invalid.
    #[error("Invalid crc32 checksum")]
    InvalidCrc32,

    /// The card has reported that something we're interacting with is using
    /// an algorithm we do not support.
    #[error("Unsupported cryptographic algorithm")]
    UnsupportedAlgorithm,

    /// Unsupported File Type
    #[error("Unsupported file type")]
    UnsupportedFileType,

    /// Bad file communication type, authentication required.
    #[error("Bad file communication type; authentication needed")]
    BadFileCommunication,

    /// Bad algorithm combination
    #[error("Bad cryptographic algorithm combination")]
    BadAlgorithm,

    /// Unsupported Communication
    #[error("Unsupported file communication")]
    UnsupportedFileCommunication,

    /// Partial write of our queued data
    #[error("incomplete write")]
    IncompleteWrite,

    // Third-party libraries here
    //
    /// Could not get random data
    #[error("Could not get random data")]
    Getrandom(getrandom::Error),
}

// vim: foldmethod=marker
