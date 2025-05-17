use std::net::{Ipv4Addr, Ipv6Addr};

use super::{Answer, Dns, DnsError, Flags, Header, Question, RData};

/// A simple byte buffer reader that tracks an internal offset.
pub struct Buffer {
    /// Internal byte buffer.
    pub data: Vec<u8>,
    /// Current read offset within the buffer.
    pub index: usize,
}

impl Buffer {
    /// Creates a new `Buffer` from a byte vector.
    pub fn new(buffer: Vec<u8>) -> Self {
        Buffer { data: buffer, index: 0 }
    }

    /// Sets the current read offset.
    pub fn set_offset(&mut self, off: usize) {
        self.index = off;
    }

    /// Reads a `u8` from the buffer.
    pub fn read_u8(&mut self) -> Result<u8, DnsError> {
        self.data.get(self.index).copied().ok_or(DnsError::EndOfBuffer).map(|val| {
            self.index += 1;
            val
        })
    }

    /// Reads a big-endian `u16` from the buffer.
    pub fn read_u16(&mut self) -> Result<u16, DnsError> {
        self.data.get(self.index..self.index + 2)
            .ok_or(DnsError::EndOfBuffer)
            .map(|bytes| {
                self.index += 2;
                u16::from_be_bytes([bytes[0], bytes[1]])
            })
    }

    /// Reads a big-endian `u32` from the buffer.
    pub fn read_u32(&mut self) -> Result<u32, DnsError> {
        self.data.get(self.index..self.index + 4)
            .ok_or(DnsError::EndOfBuffer)
            .map(|bytes| {
                self.index += 4;
                u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
            })
    }

    /// Reads `n` bytes from the buffer.
    pub fn read_n_bytes(&mut self, n: usize) -> Result<&[u8], DnsError> {
        self.data.get(self.index..self.index + n)
            .ok_or(DnsError::EndOfBuffer)
            .map(|slice| {
                self.index += n;
                slice
            })
    }

    /// Reads a DNS domain name from the buffer.
    ///
    /// Domain names are a sequence of labels prefixed by 
    /// length bytes, ending with zero.
    /// Supports compression pointers (two highest bits set) 
    /// that jump to an offset elsewhere.
    ///
    /// Returns the full domain name as a dot-separated string.
    pub fn read_string(&mut self) -> Result<String, DnsError> {
        let mut parts:  Vec<String>  = Vec::new();
        let mut jumped: bool         = false;
        let mut jump_offset: usize   = 0;

        loop {

            let len = self.read_u8()?;
            if (len & 0b1100_0000) == 0b1100_0000 {
                let next = self.read_u8()?;
                let ptr  = (((len & 0b0011_1111) as u16) << 8) | next as u16;

                if !jumped {
                    jump_offset = self.index;
                    jumped      = true;
                }

                self.set_offset(ptr as usize);
                continue;
            }

            if len == 0 {
                break;
            }

            let bytes: &[u8]  = self.read_n_bytes(len as usize)?;
            let label: String = String::from_utf8(bytes.to_vec()).unwrap();
            //println!("[DEBUG]: reading label={}", label);
            parts.push(label);
        }

        if jumped {
            self.set_offset(jump_offset);
        }

        Ok(parts.join("."))
    }

    /// Write a u8 to the buffer
    pub fn write_u8(&mut self, val: u8) {
        self.data.push(val);
    }

    /// Write a big-endian u16 to the buffer
    pub fn write_u16(&mut self, val: u16) {
        self.data.extend(&val.to_be_bytes());
    }

    /// Write a big-endian u32 to the buffer
    pub fn write_u32(&mut self, val: u32) {
        self.data.extend(&val.to_be_bytes());
    }

    /// Write n bytes to the buffer
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.data.extend(bytes);
    }

    /// Write a DNS-encoded domain name to the buffer
    /// This means splitting by dots, writing length-prefixed 
    /// labels, then a zero byte terminator.
    pub fn write_string(&mut self, name: &str) {
        if name.is_empty() {
            self.write_u8(0);
        } else {
            for label in name.split('.') {
                self.write_u8(label.len() as u8);
                self.write_bytes(label.as_bytes());
            }
            self.write_u8(0);
        }
    }
}

impl Dns {
    /// Generate a Dns structure from a buffer (deserialize from bytes)
    pub fn decode(buf: &mut Buffer) -> Result<Dns, DnsError> {
        let id        = buf.read_u16()?;
        let flags_raw = buf.read_u16()?;
        let qd_count  = buf.read_u16()?;
        let an_count  = buf.read_u16()?;
        let ns_count  = buf.read_u16()?;
        let ar_count  = buf.read_u16()?;

        let flags = Flags {
            qr     : (flags_raw  & 0x8000) != 0,
            opcode : ((flags_raw & 0x7800) >> 11) as u8,
            aa     : (flags_raw  & 0x0400) != 0,
            tc     : (flags_raw  & 0x0200) != 0,
            rd     : (flags_raw  & 0x0100) != 0,
            ra     : (flags_raw  & 0x0080) != 0,
            z      : ((flags_raw & 0x0070) >> 4) as u8,
            rcode  : (flags_raw  & 0x000F) as u8,
        };

        let header = Header {
            id,
            flags,
            qd_count,
            an_count,
            ns_count,
            ar_count,
        };

        fn decode_rdata(
            buffer: &mut Buffer, 
            atype:  u16, 
            length: u16,
            ) -> Result<RData, DnsError> {
            
            // Save the current index
            let s = buffer.index;
        
            // Reads a domain name (supports DNS name compression) 
            // from the buffer, ensuring exactly `length` bytes are 
            // consumed from the RDATA section. If the name occupies 
            // fewer bytes than `length`, remaining bytes are skipped.
            // Returns an error if more than `length` bytes are consumed 
            // (invalid RDATA).
            let mut fn_name = || -> Result<String, DnsError> {
                let name = buffer.read_string()?;
                if buffer.index > s + length as usize {
                    return Err(DnsError::InvalidRData);
                }
                // Move forward the index if the raw data
                // is more than the length, alligning the
                // index to the next record
                while buffer.index < s + length as usize {
                    buffer.read_u8()?;
                }
                Ok(name)
            };
        
            match atype {
                1 => {
                    // A record (IPv4 address)
                    let raw = buffer.read_n_bytes(length as usize)?;
                    if raw.len() != 4 {
                        return Err(DnsError::InvalidRData);
                    }
                    
                    Ok(RData::A(Ipv4Addr::new(
                        raw[0], 
                        raw[1], 
                        raw[2], 
                        raw[3])))
                }
                28 => {
                    // A record (IPv6 address)
                    let raw = buffer.read_n_bytes(length as usize)?;
                    if raw.len() != 16 {
                        return Err(DnsError::InvalidRData);
                    }
                    
                    let pts = (0..8)
                        .map(|i| 
                            u16::from_be_bytes([
                                raw[2 * i], 
                                raw[2 * i + 1]]))
                        .collect::<Vec<u16>>();
                    
                    Ok(RData::AAAA(Ipv6Addr::new(
                        pts[0], 
                        pts[1], 
                        pts[2], 
                        pts[3],
                        pts[4], 
                        pts[5], 
                        pts[6],
                        pts[7],
                    )))
                }
                // NS record (name server)
                2  => Ok(RData::NS(fn_name()?)),
                // CNAME record (canonical name)
                5  => Ok(RData::CNAME(fn_name()?)),
                _  => Ok(RData::EMPTY([])),
            }
        }


        // Parse the questions
        let mut questions = Vec::with_capacity(qd_count as usize);
        for _ in 0..qd_count {
            let qname: String  = buf.read_string()?;
            let qtype:  u16    = buf.read_u16()?;
            let qclass: u16    = buf.read_u16()?;
            questions.push(Question { qname, qtype, qclass });
        }

        // Parse the answers
        let mut answers = Vec::with_capacity(an_count as usize);
        for _ in 0..an_count {
            let aname:  String = buf.read_string()?;
            let atype:  u16    = buf.read_u16()?;
            let aclass: u16    = buf.read_u16()?;
            let ttl:    u32    = buf.read_u32()?;
            let length: u16    = buf.read_u16()?;
            let rdata:  RData  = decode_rdata(buf, atype, length)?;
            answers.push(Answer { aname, atype, aclass, ttl, length, rdata });
        }

        // Parse the authorities
        let mut authorities = Vec::with_capacity(ns_count as usize);
        for _ in 0..ns_count {
            let aname:  String = buf.read_string()?;
            let atype:  u16    = buf.read_u16()?;
            let aclass: u16    = buf.read_u16()?;
            let ttl:    u32    = buf.read_u32()?;
            let length: u16    = buf.read_u16()?;
            let rdata:  RData  = decode_rdata(buf, atype, length)?;
            authorities.push(Answer { aname, atype, aclass, ttl, length, rdata });
        }

        // Parse the additionals
        let mut additionals = Vec::with_capacity(ar_count as usize);
        for _ in 0..ar_count {
            let aname:  String = buf.read_string()?;
            let atype:  u16    = buf.read_u16()?;
            let aclass: u16    = buf.read_u16()?;
            let ttl:    u32    = buf.read_u32()?;
            let length: u16    = buf.read_u16()?;
            let rdata:  RData  = decode_rdata(buf, atype, length)?;
            additionals.push(Answer { aname, atype, aclass, ttl, length, rdata });
        }

        Ok(Dns {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    /// Convert a Dns structure into a buffer (serialize it to bytes)
    pub fn encode(&self) -> Buffer {
        let mut buffer = Buffer::new(Vec::new());

        // Compose flags u16
        let mut flags: u16 = 0;
        flags |= (self.header.flags.qr     as u16) << 15;
        flags |= (self.header.flags.opcode as u16) << 11;
        flags |= (self.header.flags.aa     as u16) << 10;
        flags |= (self.header.flags.tc     as u16) << 9;
        flags |= (self.header.flags.rd     as u16) << 8;
        flags |= (self.header.flags.ra     as u16) << 7;
        flags |= (self.header.flags.z      as u16) << 4;
        flags |=  self.header.flags.rcode  as u16;

        // Header
        buffer.write_u16(self.header.id);
        buffer.write_u16(flags);
        buffer.write_u16(self.header.qd_count);
        buffer.write_u16(self.header.an_count);
        buffer.write_u16(self.header.ns_count);
        buffer.write_u16(self.header.ar_count);

        fn encode_rdata(
            rdata: &RData,
        ) -> Result<Vec<u8>, DnsError> {
            let mut buf = Buffer::new(Vec::new());
            match rdata {
                RData::A(ipv4) => {
                    buf.write_bytes(&ipv4.octets());
                    Ok(buf.data)
                },
                RData::NS(name) | RData::CNAME(name) => {
                    buf.write_string(name);
                    Ok(buf.data)
                },
                RData::AAAA(ipv6) => {
                    for seg in &ipv6.segments() {
                        buf.write_u16(*seg);
                    }
                    Ok(buf.data)
                },
                RData::EMPTY(data) => {
                    buf.write_bytes(data);
                    Ok(buf.data)
                }
            }
        }

        // Questions
        for q in &self.questions {
            buffer.write_string(&q.qname);
            buffer.write_u16(q.qtype);
            buffer.write_u16(q.qclass);
        }

        // Answers
        for a in &self.answers {
            buffer.write_string(&a.aname);
            buffer.write_u16(a.atype);
            buffer.write_u16(a.aclass);
            buffer.write_u32(a.ttl);
            buffer.write_u16(a.length);
            let rdata_bytes = encode_rdata(&a.rdata).unwrap_or_else(|_| vec![]);
            buffer.write_u16(rdata_bytes.len() as u16);
            buffer.write_bytes(&rdata_bytes);
        }

        // Authorities
        for a in &self.authorities {
            buffer.write_string(&a.aname);
            buffer.write_u16(a.atype);
            buffer.write_u16(a.aclass);
            buffer.write_u32(a.ttl);
            buffer.write_u16(a.length);
            let rdata_bytes = encode_rdata(&a.rdata).unwrap_or_else(|_| vec![]);
            buffer.write_u16(rdata_bytes.len() as u16);
            buffer.write_bytes(&rdata_bytes);
        }

        // Additionals
        for a in &self.additionals {
            buffer.write_string(&a.aname);
            buffer.write_u16(a.atype);
            buffer.write_u16(a.aclass);
            buffer.write_u32(a.ttl);
            buffer.write_u16(a.length);
            let rdata_bytes = encode_rdata(&a.rdata).unwrap_or_else(|_| vec![]);
            buffer.write_u16(rdata_bytes.len() as u16);
            buffer.write_bytes(&rdata_bytes);
        }

        buffer
    }

    /// Add a question to the DNS message, updating the header count.
    pub fn add_question(&mut self, question: Question) {
        self.questions.push(question);
        self.header.qd_count = self.questions.len() as u16;
    }

    /// Add an answer record, updating the header count.
    pub fn add_answer(&mut self, answer: Answer) {
        self.answers.push(answer);
        self.header.an_count = self.answers.len() as u16;
    }

    /// Add an authority record, updating the header count.
    pub fn add_authority(&mut self, authority: Answer) {
        self.authorities.push(authority);
        self.header.ns_count = self.authorities.len() as u16;
    }

    pub fn add_additional(&mut self, additional: Answer) {
        self.additionals.push(additional);
        self.header.ar_count = self.additionals.len() as u16;
    }
}