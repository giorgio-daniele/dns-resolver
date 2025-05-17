use std::net::{Ipv4Addr, Ipv6Addr};

use super::{AnswerRecord, Buffer, Dns, DnsError, Flags, Header, QueryRecord, RData};

impl Dns {

    /// Convert a buffer into DNS packet (deserialize it to bytes)
    pub fn decode(buf: &mut Buffer) -> Result<Dns, DnsError> {

        // Get the fields in the header of the packet
        let id:        u16 = buf.read_u16().map_err(|_| DnsError::InvalidField)?;
        let flags_raw: u16 = buf.read_u16().map_err(|_| DnsError::InvalidField)?;
        let qd_count:  u16 = buf.read_u16().map_err(|_| DnsError::InvalidField)?;
        let an_count:  u16 = buf.read_u16().map_err(|_| DnsError::InvalidField)?;
        let ns_count:  u16 = buf.read_u16().map_err(|_| DnsError::InvalidField)?;
        let ar_count:  u16 = buf.read_u16().map_err(|_| DnsError::InvalidField)?;

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

        // Decode raw data
        fn decode_rdata(
            buffer: &mut Buffer, 
            atype:  u16, 
            length: u16,
        ) -> Result<RData, DnsError> {
            
            match atype {
                // A record (IPv4 address)
                1 => {
                    let raw = buffer.read_n_bytes(length as usize).map_err(|_| DnsError::InvalidRData)?;
                    if raw.len() != 4 {
                        return Err(DnsError::InvalidRData);
                    }
                    
                    Ok(RData::A(Ipv4Addr::new(
                        raw[0], 
                        raw[1], 
                        raw[2], 
                        raw[3])))
                }
                // AAAA record (IPv6 address)
                28 => {
                    let raw = buffer.read_n_bytes(length as usize).map_err(|_| DnsError::InvalidRData)?;
                    if raw.len() != 16 {
                        return Err(DnsError::InvalidRData);
                    }
                    
                    let pts = (0..8)
                        .map(|i| u16::from_be_bytes([raw[2 * i], raw[2 * i + 1]]))
                        .collect::<Vec<u16>>();
                    
                    Ok(RData::AAAA(Ipv6Addr::new(
                        pts[0], pts[1], pts[2], pts[3],
                        pts[4], pts[5], pts[6], pts[7],
                    )))
                }
                // NS record (name server)
                2  => {
                    let s: usize = buffer.get_index();
                    let name: String = buffer.read_str().map_err(|_| DnsError::InvalidRData)?;
                    if buffer.get_index() > s + length as usize {
                        return Err(DnsError::InvalidRData);
                    }
                    while buffer.get_index() < s + length as usize {
                        buffer.read_u8().map_err(|_| DnsError::InvalidRData)?;
                    }
                    Ok(RData::NS(name))
                },
                // CNAME record (canonical name)
                5  => {
                    let s: usize = buffer.get_index();
                    let name: String = buffer.read_str().map_err(|_| DnsError::InvalidRData)?;
                    if buffer.get_index() > s + length as usize {
                        return Err(DnsError::InvalidRData);
                    }
                    while buffer.get_index() < s + length as usize {
                        buffer.read_u8().map_err(|_| DnsError::InvalidRData)?;
                    }
                    Ok(RData::CNAME(name))
                }
                // Empty record
                _  => Ok(RData::EMPTY([])),
            }
        }

        // Parse the questions
        let mut questions = Vec::with_capacity(qd_count as usize);
        for _ in 0..qd_count {
            let qname:  String = buf.read_str().map_err(|_| DnsError::InvalidField)?;
            let qtype:  u16    = buf.read_u16().map_err(|_| DnsError::InvalidField)?;
            let qclass: u16    = buf.read_u16().map_err(|_| DnsError::InvalidField)?;
            questions.push(QueryRecord { qname, qtype, qclass });
        }

        // Parse the answers
        let mut answers = Vec::with_capacity(an_count as usize);
        for _ in 0..an_count {
            let aname:  String = buf.read_str().map_err(|_| DnsError::InvalidField)?;
            let atype:  u16    = buf.read_u16().map_err(|_| DnsError::InvalidField)?;
            let aclass: u16    = buf.read_u16().map_err(|_| DnsError::InvalidField)?;
            let ttl:    u32    = buf.read_u32().map_err(|_| DnsError::InvalidField)?;
            let length: u16    = buf.read_u16().map_err(|_| DnsError::InvalidField)?;
            let rdata:  RData  = decode_rdata(buf, atype, length)?;
            answers.push(AnswerRecord { aname, atype, aclass, ttl, length, rdata });
        }

        // Parse the authorities
        let mut authorities = Vec::with_capacity(ns_count as usize);
        for _ in 0..ns_count {
            let aname:  String = buf.read_str().map_err(|_| DnsError::InvalidField)?;
            let atype:  u16    = buf.read_u16().map_err(|_| DnsError::InvalidField)?;
            let aclass: u16    = buf.read_u16().map_err(|_| DnsError::InvalidField)?;
            let ttl:    u32    = buf.read_u32().map_err(|_| DnsError::InvalidField)?;
            let length: u16    = buf.read_u16().map_err(|_| DnsError::InvalidField)?;
            let rdata:  RData  = decode_rdata(buf, atype, length)?;
            authorities.push(AnswerRecord { aname, atype, aclass, ttl, length, rdata });
        }

        // Parse the additionals
        let mut additionals = Vec::with_capacity(ar_count as usize);
        for _ in 0..ar_count {
            let aname:  String = buf.read_str().map_err(|_| DnsError::InvalidField)?;
            let atype:  u16    = buf.read_u16().map_err(|_| DnsError::InvalidField)?;
            let aclass: u16    = buf.read_u16().map_err(|_| DnsError::InvalidField)?;
            let ttl:    u32    = buf.read_u32().map_err(|_| DnsError::InvalidField)?;
            let length: u16    = buf.read_u16().map_err(|_| DnsError::InvalidField)?;
            let rdata:  RData  = decode_rdata(buf, atype, length)?;
            additionals.push(AnswerRecord { aname, atype, aclass, ttl, length, rdata });
        }

        // Generate the DNS message
        Ok(Dns {
            header: Header {
                id       : id,
                flags    : flags,
                qd_count : qd_count,
                an_count : an_count,
                ns_count : ns_count,
                ar_count : ar_count,
            },
            questions    : questions,
            answers      : answers,
            authorities  : authorities,
            additionals  : additionals,
        })
    }

    /// Convert a Dns structure into a buffer (serialize it to bytes)
    pub fn encode(&self) -> Result<Buffer, DnsError> {
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

        // Encode raw data
        fn encode_rdata(
            rdata: &RData,
        ) -> Result<Vec<u8>, DnsError> {
            let mut buf = Buffer::new(Vec::new());
            match rdata {
                RData::A(ipv4)       => {
                    buf.write_bytes(&ipv4.octets());
                    Ok(buf.get_data().to_vec())
                },
                RData::NS(name)      => {
                    buf.write_str(name).map_err(|_| DnsError::InvalidRData)?;
                    Ok(buf.get_data().to_vec())
                },
                RData::CNAME(name)   => {
                    buf.write_str(name).map_err(|_| DnsError::InvalidRData)?;
                    Ok(buf.get_data().to_vec())
                },
                RData::AAAA(ipv6)  => {
                    for seg in &ipv6.segments() {
                        buf.write_u16(*seg);
                    }
                    Ok(buf.get_data().to_vec())
                },
                RData::EMPTY(data)  => {
                    buf.write_bytes(data);
                    Ok(buf.get_data().to_vec())
                }
            }
        }

        // Questions
        for q in &self.questions {
            buffer.write_str(&q.qname);
            buffer.write_u16(q.qtype);
            buffer.write_u16(q.qclass);
        }

        // Answers
        for a in &self.answers {
            buffer.write_str(&a.aname);
            buffer.write_u16(a.atype);
            buffer.write_u16(a.aclass);
            buffer.write_u32(a.ttl);
            buffer.write_u16(a.length);
            let raw = encode_rdata(&a.rdata).unwrap_or_else(|_| vec![]);
            buffer.write_u16(raw.len() as u16);
            buffer.write_bytes(&raw);
        }

        // Authorities
        for a in &self.authorities {
            buffer.write_str(&a.aname);
            buffer.write_u16(a.atype);
            buffer.write_u16(a.aclass);
            buffer.write_u32(a.ttl);
            buffer.write_u16(a.length);
            let raw = encode_rdata(&a.rdata).unwrap_or_else(|_| vec![]);
            buffer.write_u16(raw.len() as u16);
            buffer.write_bytes(&raw);
        }

        // Additionals
        for a in &self.additionals {
            if a.atype == 41 {
                // For OPT record, the "name" 
                // must be a single 0 byte
                buffer.write_u8(0);
            } else {
                buffer.write_str(&a.aname);
            }
            buffer.write_u16(a.atype);
            buffer.write_u16(a.aclass);
            buffer.write_u32(a.ttl);
            buffer.write_u16(a.length);
            let raw = encode_rdata(&a.rdata).unwrap_or_else(|_| vec![]);
            buffer.write_u16(raw.len() as u16);
            buffer.write_bytes(&raw);
        }

        Ok(buffer)
    }

    /// Add a question to the DNS message, updating the header count.
    pub fn add_question(&mut self, question: QueryRecord) {
        self.questions.push(question);
        self.header.qd_count = self.questions.len() as u16;
    }

    /// Add an answer record, updating the header count.
    pub fn add_answer(&mut self, answer: AnswerRecord) {
        self.answers.push(answer);
        self.header.an_count = self.answers.len() as u16;
    }

    /// Add an authority record, updating the header count.
    pub fn add_authority(&mut self, authority: AnswerRecord) {
        self.authorities.push(authority);
        self.header.ns_count = self.authorities.len() as u16;
    }

    /// Add an additional record, updating the header count
    pub fn add_additional(&mut self, additional: AnswerRecord) {
        self.additionals.push(additional);
        self.header.ar_count = self.additionals.len() as u16;
    }
}
