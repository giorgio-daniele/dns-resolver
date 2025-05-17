/// A simple byte buffer reader that tracks an internal offset.
#[derive(Debug)]
pub struct Buffer {
    data: Vec<u8>,
    index: usize,
}

#[derive(Debug)]
pub enum BufferError {
    EndOfBuffer,
    InvalidString,
}

impl Buffer {
    /// Creates a new `Buffer` from a byte vector.
    pub fn new(buffer: Vec<u8>) -> Self {
        Buffer { data: buffer, index: 0 }
    }

    /// Sets the current read offset.
    pub fn set_index(&mut self, off: usize) -> Result<(), BufferError> {
        if off >= self.data.len() {
            return Err(BufferError::EndOfBuffer);
        }
        self.index = off;
        Ok(())
    }

    /// Get the current data stored within the buffer
    pub fn get_data(&self) -> &[u8] {
        &self.data
    }

    /// Get the current index
    pub fn get_index(&self) -> usize {
        self.index
    }

    /// Reads a `u8` from the buffer.
    pub fn read_u8(&mut self) -> Result<u8, BufferError> {
        self.data
            .get(self.index)
            .copied()
            .ok_or(BufferError::EndOfBuffer)
            .map(|byte| {
                self.index += 1;
                byte
            })
    }

    /// Reads a big-endian `u16` from the buffer.
    pub fn read_u16(&mut self) -> Result<u16, BufferError> {
        self.data
            .get(self.index..self.index + 2)
            .ok_or(BufferError::EndOfBuffer)
            .map(|bytes| {
                self.index += 2;
                u16::from_be_bytes([bytes[0], bytes[1]])
            })
    }

    /// Reads a big-endian `u32` from the buffer.
    pub fn read_u32(&mut self) -> Result<u32, BufferError> {
        self.data
            .get(self.index..self.index + 4)
            .ok_or(BufferError::EndOfBuffer)
            .map(|bytes| {
                self.index += 4;
                u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
            })
    }

    /// Reads `n` bytes from the buffer.
    pub fn read_n_bytes(&mut self, n: usize) -> Result<&[u8], BufferError> {
        self.data
            .get(self.index..self.index + n)
            .ok_or(BufferError::EndOfBuffer)
            .map(|bytes| {
                self.index += n;
                bytes
            })
    }

    /// Read a string (according to DNS format)
    pub fn read_str(&mut self) -> Result<String, BufferError> {
        let mut parts: Vec<String> = Vec::new();
        let mut jumped:       bool = false;
        let mut jump_offset: usize = 0;

        loop {
            let len = self.read_u8()?;
            
            // Pointer label (compression)
            if (len & 0b1100_0000) == 0b1100_0000 {
                let next: u8  = self.read_u8()?;
                let petr: u16 = (((len & 0b0011_1111) as u16) << 8) | next as u16;

                // Prevent infinite loops / pointers to themselves or beyond buffer
                if petr as usize >= self.data.len() {
                    return Err(BufferError::InvalidString);
                }

                if !jumped {
                    jump_offset = self.index;
                    jumped = true;
                }

                // Jump to pointer location
                self.set_index(petr as usize)?;
                continue;
            }

            // Zero length means end of the domain name
            if len == 0 {
                break;
            }

            // Read the label
            let bytes  = self.read_n_bytes(len as usize)?;
            let label = String::from_utf8(bytes.to_vec())
                .map_err(|_| BufferError::InvalidString)?;
            parts.push(label);
        }

        // If we jumped, restore index to 
        // the position after pointer bytes
        if jumped {
            self.set_index(jump_offset)?;
        }

        // Return "." if no parts (root domain)
        Ok(if parts.is_empty() {
            ".".to_string()
        } else {
            parts.join(".")
        })
    }

    /// Appends a `u8` to the buffer.
    pub fn write_u8(&mut self, value: u8) {
        self.data.push(value);
    }

    /// Appends a big-endian `u16` to the buffer.
    pub fn write_u16(&mut self, value: u16) {
        self.data.extend_from_slice(&value.to_be_bytes());
    }

    /// Appends a big-endian `u32` to the buffer.
    pub fn write_u32(&mut self, value: u32) {
        self.data.extend_from_slice(&value.to_be_bytes());
    }

    /// Appends raw bytes to the buffer.
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }

    /// Write a string (according to DNS format)
    pub fn write_str(&mut self, name: &str) -> Result<(), BufferError> {
        for label in name.split('.') {
            let len = label.len();
            if len > 63 {
                return Err(BufferError::InvalidString);
            }
            self.write_u8(len as u8);
            self.write_bytes(label.as_bytes());
        }
        self.write_u8(0); // Null byte to terminate the name
        Ok(())
    }
}
