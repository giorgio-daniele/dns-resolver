use std::str;

use crate::types::{DnsBufferError, DnsReadBuffer, DnsWriteBuffer};

impl<'a> DnsReadBuffer<'a> {
    /// Creates a new `DnsReadBuffer` to read from the given byte slice.
    ///
    /// # Arguments
    /// * `data` - The byte slice containing DNS message data.
    ///
    /// # Returns
    /// A new `DnsReadBuffer` instance with read index set to 0.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, index: 0 }
    }

    /// Returns the current read index.
    pub fn get_index(&self) -> usize {
        self.index
    }

    /// Sets the read index to the specified offset.
    ///
    /// Returns an error if the offset is beyond the end of the buffer.
    ///
    /// # Arguments
    /// * `off` - The offset to set as the current read position.
    ///
    /// # Returns
    /// `Ok(&mut Self)` on success, or `Err(DnsBufferError::EndOfBuffer)` if offset is invalid.
    pub fn set_index(&mut self, off: usize) -> Result<&mut Self, DnsBufferError> {
        if off >= self.data.len() {
            return Err(DnsBufferError::EndOfBuffer);
        }
        self.index = off;
        Ok(self)
    }

    /// Reads a single byte (`u8`) from the buffer.
    ///
    /// Advances the read index by 1 on success.
    ///
    /// # Errors
    /// Returns `DnsBufferError::EndOfBuffer` if reading beyond available data.
    pub fn read_u8(&mut self) -> Result<u8, DnsBufferError> {
        self.data
            .get(self.index)
            .copied()
            .ok_or(DnsBufferError::EndOfBuffer)
            .map(|b| {
                self.index += 1;
                b
            })
    }

    /// Reads a 16-bit unsigned integer (`u16`) in big-endian order from the buffer.
    ///
    /// Advances the read index by 2 on success.
    ///
    /// # Errors
    /// Returns `DnsBufferError::EndOfBuffer` if reading beyond available data.
    pub fn read_u16(&mut self) -> Result<u16, DnsBufferError> {
        self.data
            .get(self.index..self.index + 2)
            .ok_or(DnsBufferError::EndOfBuffer)
            .map(|b| {
                self.index += 2;
                u16::from_be_bytes([b[0], b[1]])
            })
    }

    /// Reads a 32-bit unsigned integer (`u32`) in big-endian order from the buffer.
    ///
    /// Advances the read index by 4 on success.
    ///
    /// # Errors
    /// Returns `DnsBufferError::EndOfBuffer` if reading beyond available data.
    pub fn read_u32(&mut self) -> Result<u32, DnsBufferError> {
        self.data
            .get(self.index..self.index + 4)
            .ok_or(DnsBufferError::EndOfBuffer)
            .map(|b| {
                self.index += 4;
                u32::from_be_bytes([b[0], b[1], b[2], b[3]])
            })
    }

    /// Reads `n` bytes from the buffer as a slice.
    ///
    /// Advances the read index by `n` on success.
    ///
    /// # Arguments
    /// * `n` - Number of bytes to read.
    ///
    /// # Errors
    /// Returns `DnsBufferError::EndOfBuffer` if reading beyond available data.
    pub fn read_n_bytes(&mut self, n: usize) -> Result<&'a [u8], DnsBufferError> {
        self.data
            .get(self.index..self.index + n)
            .ok_or(DnsBufferError::EndOfBuffer)
            .map(|b| {
                self.index += n;
                b
            })
    }

    /// Reads a DNS domain name from the buffer, supporting pointer compression.
    ///
    /// Returns the decoded domain name as a `String` and updates the read index.
    ///
    /// # Errors
    /// Returns `DnsBufferError::EndOfBuffer` if buffer ends unexpectedly.
    /// Returns `DnsBufferError::InvalidString` if invalid compression pointers or invalid UTF-8 are encountered.
    pub fn read_str(&mut self) -> Result<String, DnsBufferError> {
        let (name, new_index) = Self::read_name_at(self.data, self.index)?;
        self.index = new_index;
        Ok(name)
    }

    /// Internal helper function to read a DNS name at a given position in the buffer.
    ///
    /// Recursively handles pointer-based compression.
    ///
    /// Returns a tuple of `(decoded_name, next_index_after_name)`.
    ///
    /// # Arguments
    /// * `data` - The DNS message byte slice.
    /// * `idx` - The starting index to read the name from.
    ///
    /// # Errors
    /// Returns errors if reading outside bounds, invalid pointers, or invalid UTF-8 occurs.
    fn read_name_at(data: &'a [u8], mut idx: usize) -> Result<(String, usize), DnsBufferError> {
        let mut labels = Vec::new();
        let mut jumped = false;
        let mut jump_index = 0;

        loop {
            let len = *data.get(idx).ok_or(DnsBufferError::EndOfBuffer)?;
            idx += 1;

            // Check if this is a pointer (2 most significant bits set)
            if (len & 0b1100_0000) == 0b1100_0000 {
                let b2 = *data.get(idx).ok_or(DnsBufferError::EndOfBuffer)?;
                idx += 1;

                let pointer = (((len & 0b0011_1111) as usize) << 8) | (b2 as usize);

                if pointer >= data.len() {
                    return Err(DnsBufferError::InvalidString);
                }

                // Save current index if this is the first jump
                if !jumped {
                    jump_index = idx;
                    jumped = true;
                }

                // Recursively read name at pointer location
                let (name, _) = Self::read_name_at(data, pointer)?;
                labels.push(name);
                break;
            }

            // Zero length indicates end of domain name
            if len == 0 {
                break;
            }

            // Read label of `len` bytes
            let end = idx + (len as usize);
            let label_bytes = data.get(idx..end).ok_or(DnsBufferError::EndOfBuffer)?;
            idx = end;

            // Convert label bytes to UTF-8 string
            let label = str::from_utf8(label_bytes).map_err(|_| DnsBufferError::InvalidString)?;
            labels.push(label.to_string());
        }

        Ok((
            if labels.is_empty() {
                ".".to_string()
            } else {
                labels.join(".")
            },
            if jumped { jump_index } else { idx },
        ))
    }
}

impl DnsWriteBuffer {
    /// Creates a new empty `DnsWriteBuffer`.
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Writes a single byte to the buffer.
    ///
    /// # Arguments
    /// * `value` - The byte to write.
    ///
    /// # Returns
    /// `Ok(&mut Self)` on success.
    pub fn write_u8(&mut self, value: u8) {
        self.data.push(value);
    }

    /// Writes a 16-bit unsigned integer in big-endian order to the buffer.
    ///
    /// # Arguments
    /// * `value` - The `u16` value to write.
    ///
    /// # Returns
    /// `Ok(&mut Self)` on success.
    pub fn write_u16(&mut self, value: u16) {
        self.data.extend_from_slice(&value.to_be_bytes());
    }

    /// Writes a 32-bit unsigned integer in big-endian order to the buffer.
    ///
    /// # Arguments
    /// * `value` - The `u32` value to write.
    ///
    /// # Returns
    /// `Ok(&mut Self)` on success.
    pub fn write_u32(&mut self, value: u32) {
        self.data.extend_from_slice(&value.to_be_bytes());
    }

    /// Writes raw bytes to the buffer.
    ///
    /// # Arguments
    /// * `bytes` - The byte slice to write.
    ///
    /// # Returns
    /// `Ok(&mut Self)` on success.
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }

    /// Consumes the buffer and returns the inner byte vector.
    pub fn into_inner(self) -> Vec<u8> {
        self.data
    }

    /// Writes a DNS domain name to the buffer, without compression.
    ///
    /// Splits the name by `.` and writes each label preceded by its length,
    /// followed by a zero-length byte to terminate the name.
    ///
    /// # Arguments
    /// * `name` - The domain name string to write.
    ///
    /// # Errors
    /// Returns `DnsBufferError::LabelTooLong` if any label exceeds 63 bytes.
    ///
    /// # Returns
    /// `Ok(&mut Self)` on success.
    pub fn write_str(&mut self, name: &str) -> Result<(), DnsBufferError> {
        for label in name.split('.') {
            let len = label.len();
            if len > 63 {
                return Err(DnsBufferError::LabelTooLong);
            }
            self.write_u8(len as u8);
            self.write_bytes(label.as_bytes());
        }
        self.write_u8(0);
        Ok(())
    }
}
