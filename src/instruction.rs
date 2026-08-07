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

/// Instructions are single-byte commands followed by a well-defined
/// amount of data. These are sent as the first byte of an APDU to the
/// DESFire card.
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum Instruction {
    // Control-flow instructions
    //
    /// Get the next hunk of data that we know is there because we just got
    /// back a AdditionalData response code.
    AdditionalData = 0xAF,

    // Context-dependent commands. These commands have different meanings
    // depending on an open application (or not).
    //
    /// Get key settings for the open Application
    GetKeySettings = 0x45,

    // /// Change the key for a specific key slot.
    // ChangeKeySettings = 0x54,
    //
    /// Get the key version for a Key ID
    GetKeyVersion = 0x64,

    /// Authenticate with the Card (DES)
    AuthenticateDes = 0x1A,

    /// Authenticate with the Card (AES)
    AuthenticateAes = 0xAA,

    /// Change the key for a specific key slot.
    ChangeKey = 0xC4,

    //
    // GetFreeMemory = 0x6E,

    // Instructions that are about the "global" state of the card.
    //
    /// Request the card version
    GetVersionInfo = 0x60,

    /// Get the installed Application IDs.
    GetApplicationIdList = 0x6A,

    /// Get the card's real UID
    GetUid = 0x51,

    /// Set a bit of card configuration. This accepts a second argument
    /// (which is the "key" that you're setting).
    SetConfiguration = 0x5C,

    /// Format the Card
    FormatCard = 0xFC,

    // Instructions that are about working with applications
    //
    /// Select an application
    SelectApplication = 0x5A,

    /// Create an application
    CreateApplication = 0xCA,

    /// Delete an application
    DeleteApplication = 0xDA,

    // Instructions that deal with file operations
    //
    /// Create a data file
    CreateDataFile = 0xCD,

    // GetDataFileNames = 0x6D (Am I reading this right?)
    //   -> Maybe 0xD6 to set it? A lot of the write opcodes are flipped,
    //      like  0x45/0x54 or 0xF5/0x5F
    //
    // CreateBackupDataFile = 0xCB,
    // CreateValueFile = 0xCC,
    // CreateLinearRecordFile = 0xC1
    // CreateCyclicRecordFile = 0xC0
    //
    /// Write to a Data File
    WriteDataFile = 0x3D,

    /// Read to a Data File
    ReadDataFile = 0xBD,

    // ReadValueFile = 0x6C
    // CreditValueFile = 0x0C
    // DebitValueFile = 0xDC
    // LimitedCreditValueFile = 0x1C
    //
    // WriteRecordFile = 0x3B,
    // ReadRecordFile = 0xBB,
    // ClearRecordFile = 0xEB,
    //
    /// Get file settings back off the card
    GetFileSettings = 0xF5,

    // /// Set file settings
    // ChangeFileSettings = 0x5F,
    //
    /// List files in an application
    ListFiles = 0x6F,

    /// Delete a file
    DeleteFile = 0xDF,
    //
    // CommitTransaction = 0xC7,
    // AbortTransaction = 0xA7
}

// vim: foldmethod=marker
