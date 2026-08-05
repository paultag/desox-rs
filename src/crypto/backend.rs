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

/// Generic cryptographic backend usable as part of the DESFire scheme. This is
/// usually something like DES or AES-128 in CBC block mode. This trait exists
/// to collapse the external dependencies and traits into a single trait that
/// we can implement with a specific backend.
///
/// Currently the block size and key size are assumed to be the same (BLOCK_SIZE),
/// which is *NOT* a good assumption. However, I didn't/don't plan on adding
/// 3DES right now, but when/if I do, BLOCK_SIZE will likely need to change,
/// and change throughout the codebase.
///
/// As of right now, we're using the [des] and [aes] crates.
pub trait Backend<const BLOCK_SIZE: usize>
where
    Self::Encryptor: BackendEncryptor<BLOCK_SIZE>,
    Self::Decryptor: BackendDecryptor<BLOCK_SIZE>,
{
    /// Type that implements the 'Encryptor' trait -- CBC Block mode
    /// encryption for a specific algorithm (and block size).
    type Encryptor;

    /// Object that contains the decryption state
    type Decryptor;

    /// Create a new [Backend] of the underlying algorithm,
    /// initialized to the "Zero IV" state.
    fn new(key: [u8; BLOCK_SIZE]) -> Self;

    /// Set the IV manually.
    fn set_iv(&mut self, iv: [u8; BLOCK_SIZE]);

    /// Get the current IV state.
    fn get_iv(&self) -> &[u8; BLOCK_SIZE];

    /// Get the current sesion key.
    fn get_key(&self) -> &[u8; BLOCK_SIZE];

    /// Return a handle to the "Decryptor" -- something which implements
    /// [BackendDecryptor], used to decrypt messages using the
    /// session keying state.
    fn decryptor(&self) -> Self::Decryptor;

    /// Decrypt once -- updating the IV state.
    fn decrypt(&mut self, data: &mut [u8]) {
        let iv: &[u8; BLOCK_SIZE] = &data[data.len() - BLOCK_SIZE..].try_into().unwrap();
        self.decryptor().decrypt(data);
        self.set_iv(*iv);
    }

    /// Return a handle to the "Encryptor" -- something which implements
    /// [BackendEncryptor], used to encrypt messages using the
    /// session keying state.
    fn encryptor(&self) -> Self::Encryptor;

    /// Encrypt once -- updating the IV state.
    fn encrypt(&mut self, data: &mut [u8]) {
        self.encryptor().encrypt(data);
        let iv: &[u8; BLOCK_SIZE] = &data[data.len() - BLOCK_SIZE..].try_into().unwrap();
        self.set_iv(*iv);
    }

    /// Generate CMAC keys "K1" and "K2" for the current keying status.
    /// Generating keys generally requires the IV to be all zero, and
    /// computing the CMAC will alter the IV state of the backend.
    ///
    /// Since the backend is unusable after this, we force consume it to avoid
    /// bugs.
    fn generate_cmac_keys(self) -> ([u8; BLOCK_SIZE], [u8; BLOCK_SIZE]);
}

/// Encryptor state -- this is a CBC block mode for some algorithm.
pub trait BackendEncryptor<const BLOCK_SIZE: usize> {
    /// Encrypt a block of data in-place. The resulting data will be block
    /// aligned -- any unpadding needs to be done on the resulting data if
    /// required.
    ///
    /// This will NOT update the internal IV.
    fn encrypt(&mut self, data: &mut [u8]);
}

/// Decryptor state -- this is a CBC block mode for some algorithm.
pub trait BackendDecryptor<const BLOCK_SIZE: usize> {
    /// Decrypt a block of data in-place. The input data *MUST* be block
    /// aligned -- any padding MUST be done before getting to the backend
    /// if required.
    ///
    /// This will NOT update the internal IV.
    fn decrypt(&mut self, data: &mut [u8]);
}

// vim: foldmethod=marker
