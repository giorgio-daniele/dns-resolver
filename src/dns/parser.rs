use std::net::{Ipv4Addr, Ipv6Addr};

use super::{Answer, Dns, DnsError, Flags, Header, Question};

/// A simple byte buffer reader that tracks an internal offset.
pub struct Buffer {
    /// Internal byte buffer.
    pub data: Vec<u8>,
    /// Current read offset within the buffer.
    pub idex: usize,
}

impl Buffer {
    /// Creates a new `Buffer` from a byte vector.
    pub fn new(buffer: Vec<u8>) -> Self {
        Buffer {
            data: buffer,
            idex: 0,
        }
    }

    /// Sets the current read offset.
    pub fn set_offset(&mut self, off: usize) {
        self.idex = off;
    }

    /// Reads a `u8` from the buffer.
    pub fn read_u8(&mut self) -> Result<u8, DnsError> {
        if self.idex + 1 > self.data.len() {
            return Err(DnsError::EndOfBuffer);
        }
        let val = self.data[self.idex];
        self.idex += 1;
        Ok(val)
    }

    /// Reads a big-endian `u16` from the buffer.
    pub fn read_u16(&mut self) -> Result<u16, DnsError> {
        if self.idex + 2 > self.data.len() {
            return Err(DnsError::EndOfBuffer);
        }
        let val = u16::from_be_bytes([
            self.data[self.idex],
            self.data[self.idex + 1],
        ]);
        self.idex += 2;
        Ok(val)
    }

    /// Reads a big-endian `u32` from the buffer.
    pub fn read_u32(&mut self) -> Result<u32, DnsError> {
        if self.idex + 4 > self.data.len() {
            return Err(DnsError::EndOfBuffer);
        }
        let val = u32::from_be_bytes([
            self.data[self.idex],
            self.data[self.idex + 1],
            self.data[self.idex + 2],
            self.data[self.idex + 3],
        ]);
        self.idex += 4;
        Ok(val)
    }

    /// Reads `n` bytes from the buffer.
    pub fn read_n_bytes(&mut self, n: usize) -> Result<&[u8], DnsError> {
        if self.idex + n > self.data.len() {
            return Err(DnsError::EndOfBuffer);
        }
        let slice = &self.data[self.idex..self.idex + n];
        self.idex += n;
        Ok(slice)
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
                    jump_offset = self.idex;
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
            // Root label, just write 0
            self.write_u8(0);
        } else {
            for label in name.split('.') {
                let len = label.len() as u8;
                self.write_u8(len);
                self.write_bytes(label.as_bytes());
            }
            self.write_u8(0); // terminator
        }
    }

}




impl Dns {
    /// Generate a Dns structure from a buffer (deserialize from bytes)
    pub fn decode(buf: &mut Buffer) -> Result<Dns, DnsError> {
        let id       = buf.read_u16()?;
        let flags_raw= buf.read_u16()?;
        let qd_count = buf.read_u16()?;
        let an_count = buf.read_u16()?;
        let ns_count = buf.read_u16()?;
        let ar_count = buf.read_u16()?;

        let flags = Flags {
            qr    : (flags_raw  & 0x8000) != 0,
            opcode: ((flags_raw & 0x7800) >> 11) as u8,
            aa    : (flags_raw  & 0x0400) != 0,
            tc    : (flags_raw  & 0x0200) != 0,
            rd    : (flags_raw  & 0x0100) != 0,
            ra    : (flags_raw  & 0x0080) != 0,
            z     : ((flags_raw & 0x0070) >> 4) as u8,
            rcode : (flags_raw  & 0x000F) as u8,
        };

        let header = Header {
            id,
            flags,
            qd_count,
            an_count,
            ns_count,
            ar_count,
        };

        let mut questions = Vec::with_capacity(qd_count as usize);
        for _ in 0..qd_count {
            let qname:  String  = buf.read_string()?;
            let qtype:  u16     = buf.read_u16()?;
            let qclass: u16     = buf.read_u16()?;
        
            questions.push(Question {
                qname,
                qtype,
                qclass,
            });
        }

        let mut answers = Vec::with_capacity(an_count as usize);
        for _ in 0..an_count {
            let aname:  String  = buf.read_string()?;
            let atype:  u16     = buf.read_u16()?;
            let aclass: u16     = buf.read_u16()?;
            let ttl:    u32     = buf.read_u32()?;
            let length: u16     = buf.read_u16()?;
            let rdata:  Vec<u8> = buf.read_n_bytes(length as usize)?.to_vec();
        
            answers.push(Answer {
                aname,
                atype,
                aclass,
                ttl,
                length,
                rdata,
            });
        }

        let mut authorities = Vec::with_capacity(ns_count as usize);
        for _ in 0..ns_count {
            let aname:  String = buf.read_string()?;
            let atype:  u16    = buf.read_u16()?;
            let aclass: u16    = buf.read_u16()?;
            let ttl:    u32    = buf.read_u32()?;
            let length: u16    = buf.read_u16()?;
            let rdata: Vec<u8> = buf.read_n_bytes(length as usize)?.to_vec();
        
            authorities.push(Answer {
                aname,
                atype,
                aclass,
                ttl,
                length,
                rdata,
            });
        }
        
        let mut additionals = Vec::with_capacity(ar_count as usize);
        for _ in 0..ar_count {
            let aname:  String = buf.read_string()?;
            let atype:  u16    = buf.read_u16()?;
            let aclass: u16    = buf.read_u16()?;
            let ttl:    u32    = buf.read_u32()?;
            let length: u16    = buf.read_u16()?;
            let rdata: Vec<u8> = buf.read_n_bytes(length as usize)?.to_vec();
        
            additionals.push(Answer {
                aname,
                atype,
                aclass,
                ttl,
                length,
                rdata,
            });
        }

        Ok(Dns {
            header      : header,
            questions   : questions,
            answers     : answers,
            authorities : authorities,
            additionals : additionals

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
            buffer.write_bytes(&a.rdata);
        }
    
        // Authorities
        for a in &self.authorities {
            buffer.write_string(&a.aname);
            buffer.write_u16(a.atype);
            buffer.write_u16(a.aclass);
            buffer.write_u32(a.ttl);
            buffer.write_u16(a.length);
            buffer.write_bytes(&a.rdata);
        }
    
        // Additionals
        for a in &self.additionals {
            buffer.write_string(&a.aname);
            buffer.write_u16(a.atype);
            buffer.write_u16(a.aclass);
            buffer.write_u32(a.ttl);
            buffer.write_u16(a.length);
            buffer.write_bytes(&a.rdata);
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

    /// Add an additional record, updating the header count.
    pub fn add_additional(&mut self, additional: Answer) {
        self.additionals.push(additional);
        self.header.ar_count = self.additionals.len() as u16;
    }

    /// Add DNSO extension, a way for saying the name server
    /// that DNS packets over 512 bytes are allowed
    pub fn add_opt_record(&mut self, size: u16) {
        let opt_record = Answer {
            aname:  String::from(""),  // root label
            atype:  41,                // OPT record type
            aclass: size,              // UDP payload size
            ttl:    0,                 // extended RCODE and flags, usually 0
            length: 0,                 // no data options
            rdata:  vec![],
        };
        self.add_additional(opt_record);
    }
 
}


#[derive(Debug)]
pub enum RData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    NS(String),
    CNAME(String),
}

impl Answer {
    pub fn get_rdata(&self) -> Result<RData, DnsError> {
        match self.atype {
            1 => {
                let addr = Ipv4Addr::new(
                    self.rdata[0], 
                    self.rdata[1],
                    self.rdata[2], 
                    self.rdata[3]
                );
                Ok(RData::A(addr))
            },
            // 2 | 5 => {
                // Extract the name (in DNS encoding)
            // },
            28 => {
                let addr: [u16; 8] = [
                    u16::from_be_bytes([self.rdata[0],  self.rdata[1]]),
                    u16::from_be_bytes([self.rdata[2],  self.rdata[3]]),
                    u16::from_be_bytes([self.rdata[4],  self.rdata[5]]),
                    u16::from_be_bytes([self.rdata[6],  self.rdata[7]]),
                    u16::from_be_bytes([self.rdata[8],  self.rdata[9]]),
                    u16::from_be_bytes([self.rdata[10], self.rdata[11]]),
                    u16::from_be_bytes([self.rdata[12], self.rdata[13]]),
                    u16::from_be_bytes([self.rdata[14], self.rdata[15]]),
                ];
                Ok(RData::AAAA(Ipv6Addr::new(
                    addr[0], 
                    addr[1], 
                    addr[2], 
                    addr[3],
                    addr[4], 
                    addr[5], 
                    addr[6],
                    addr[7]
                )))
            }
            _ => Err(DnsError::UnsupportedRecordType),
        }
    }
}