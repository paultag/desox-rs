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

use crate::Uid;

/// Unparsed version info struct
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct VersionInfo {
    /// Hardware Version Information
    pub hardware: DetailedVersionInfo,

    /// Software Version Information
    pub software: DetailedVersionInfo,

    /// Card UID. This may not be the real one depending on a few different
    /// factors. You may need to authenticate and call get_real_uid rather
    /// than using this field.
    pub uid: Uid,

    /// Batch Number
    pub production_batch_number: [u8; 5],

    /// Calendar week this was made
    pub production_calendar_week: u8,

    /// Year this device was manufactured.
    pub production_year: u8,
}

impl VersionInfo {
    /// Parse [VersionInfo] from a fixed-sized array.
    pub fn parse(v: &[u8; 28]) -> Self {
        let hardware = DetailedVersionInfo::parse(v[..7].try_into().unwrap());
        let software = DetailedVersionInfo::parse(v[7..14].try_into().unwrap());
        let uid: Uid = v[14..21].try_into().unwrap();
        let production_batch_number: [u8; 5] = v[21..26].try_into().unwrap();
        let production_calendar_week = v[26];
        let production_year = v[27];

        Self {
            hardware,
            software,
            uid,
            production_batch_number,
            production_calendar_week,
            production_year,
        }
    }
}

/// Unparsed version info for Hardware/Software versions.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct DetailedVersionInfo {
    /// Vendor ID field. 0x04 for NXP.
    pub vendor_id: u8,

    /// Type (0x01 always?)
    pub r#type: u8,

    /// Sub-type (0x01 always?)
    pub sub_type: u8,

    /// Major version of the hardware/software
    pub major_version: u8,

    /// Minor version of the hardware/software
    pub minor_version: u8,

    /// Storage size (0x18 for 4k)
    pub storage_size: u8,

    /// Protocol type (0x05 for ISO1443-2, -3, -4?)
    pub protocol_type: u8,
}

impl DetailedVersionInfo {
    /// Parse [DetailedVersionInfo] from a fixed-sized array.
    pub fn parse(v: &[u8; 7]) -> Self {
        let [
            vendor_id,
            r#type,
            sub_type,
            major_version,
            minor_version,
            storage_size,
            protocol_type,
        ] = *v;

        Self {
            vendor_id,
            r#type,
            sub_type,
            major_version,
            minor_version,
            storage_size,
            protocol_type,
        }
    }
}

// vim: foldmethod=marker
