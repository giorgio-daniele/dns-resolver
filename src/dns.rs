use crate::types::{
    AnswerRecord, 
    Dns, 
    DnsError,
    DnsReadBuffer, 
    DnsWriteBuffer, 
    Flags, 
    Header, 
    QueryRecord, 
    RData, 
    Type,
};
use std::net::{Ipv4Addr, Ipv6Addr};

impl Dns {
    /// Encodes DNS flags into a 16-bit integer.
    fn encode_flags(flags: &Flags) -> u16 {
        ((flags.qr as u16) << 15)
            | ((flags.opcode as u16) << 11)
            | ((flags.aa as u16) << 10)
            | ((flags.tc as u16) << 9)
            | ((flags.rd as u16) << 8)
            | ((flags.ra as u16) << 7)
            | ((flags.z as u16) << 4)
            | (flags.rcode as u16)
    }

    /// Decodes a 16-bit integer into DNS flags.
    fn decode_flags(raw: u16) -> Flags {
        Flags {
            qr:     (raw & 0x8000) != 0,
            opcode: ((raw & 0x7800) >> 11) as u8,
            aa:     (raw & 0x0400) != 0,
            tc:     (raw & 0x0200) != 0,
            rd:     (raw & 0x0100) != 0,
            ra:     (raw & 0x0080) != 0,
            z:      ((raw & 0x0070) >> 4) as u8,
            rcode:  (raw & 0x000F) as u8,
        }
    }

    /// Decodes a resource data section based on type and length.
    fn decode_rdata(
        buf:    &mut DnsReadBuffer, 
        atype:  u16, 
        length: u16) 
    -> Result<RData, DnsError> {
        match atype {
            1 => {
                let raw = buf.read_n_bytes(length as usize).map_err(|_| DnsError::InvalidField)?;
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
                let raw = buf.read_n_bytes(length as usize).map_err(|_| DnsError::InvalidField)?;
                if raw.len() != 16 {
                    return Err(DnsError::InvalidRData);
                }
                let parts = (0..8)
                    .map(|i| u16::from_be_bytes([raw[2 * i], raw[2 * i + 1]]))
                    .collect::<Vec<_>>();
                Ok(RData::AAAA(Ipv6Addr::new(
                    parts[0],
                    parts[1], 
                    parts[2], 
                    parts[3],
                    parts[4], 
                    parts[5], 
                    parts[6], 
                    parts[7],
                )))
            }
            2 | 5 => {
                let stat = buf.get_index();
                let name = buf.read_str().map_err(|_| DnsError::InvalidField)?;
                if buf.get_index() > stat + length as usize {
                    return Err(DnsError::InvalidRData);
                }
                while buf.get_index() < stat + length as usize {
                    buf.read_u8().map_err(|_| DnsError::InvalidField)?;
                }
                match atype {
                    2 => Ok(RData::NS(name)),
                    5 => Ok(RData::CNAME(name)),
                    _ => unreachable!(),
                }
            }
            _ => Ok(RData::EMPTY([])),
        }
    }

    /// Decodes a list of query records from the buffer.
    fn decode_questions(
        buf:   &mut DnsReadBuffer, 
        count: u16) 
    -> Result<Vec<QueryRecord>, DnsError> {
        let mut records = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let qname  = buf.read_str().map_err(|_| DnsError::InvalidField)?;
            let qtype     = buf.read_u16().map_err(|_| DnsError::InvalidField)?;
            let qclass    = buf.read_u16().map_err(|_| DnsError::InvalidField)?;
            records.push(QueryRecord { qname, qtype, qclass });
        }
        Ok(records)
    }

    /// Decodes a list of answer or authority/additional records.
    fn decode_answers(
        buf:   &mut DnsReadBuffer, 
        count: u16) 
    -> Result<Vec<AnswerRecord>, DnsError> {
        let mut records = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let aname  = buf.read_str().map_err(|_| DnsError::InvalidField)?;
            let atype     = buf.read_u16().map_err(|_| DnsError::InvalidField)?;
            let aclass    = buf.read_u16().map_err(|_| DnsError::InvalidField)?;
            let ttl       = buf.read_u32().map_err(|_| DnsError::InvalidField)?;
            let length    = buf.read_u16().map_err(|_| DnsError::InvalidField)?;
            let rdata   = Self::decode_rdata(buf, atype, length)?;

            records.push(AnswerRecord {
                aname, atype, aclass, ttl, length, rdata,
            });
        }
        Ok(records)
    }

    /// Encodes a list of answer, authority, or additional records.
    fn encode_answers(
        buffer:  &mut DnsWriteBuffer,
        answers: &[AnswerRecord],
    ) -> Result<(), DnsError> {
        for a in answers {
            if a.atype == 41 {
                buffer.write_u8(0);
            } else {
                buffer.write_str(&a.aname);
            }
            buffer.write_u16(a.atype);
            buffer.write_u16(a.aclass);
            buffer.write_u32(a.ttl);

            let raw = Self::encode_rdata(&a.rdata)?;
            buffer.write_u16(raw.len() as u16);
            buffer.write_bytes(&raw);
        }
        Ok(())
    }

    /// Encodes a single RData into bytes for writing.
    fn encode_rdata(rdata: &RData) -> Result<Vec<u8>, DnsError> {
        let mut buf = DnsWriteBuffer { data: Vec::new() };

        match rdata {
            RData::A(ipv4) => {
                buf.write_bytes(&ipv4.octets());
            }
            RData::AAAA(ipv6) => {
                for seg in ipv6.segments() {
                    buf.write_u16(seg);
                }
            }
            RData::NS(name) | RData::CNAME(name)  => {
            // RData::NS(name) | RData::CNAME(name) | RData::PTR(name) => {
                buf.write_str(name);
            }
            // RData::TXT(text) => {
            //     let bytes = text.as_bytes();
            //     if bytes.len() > 255 {
            //         return Err(DnsError::InvalidField);
            //     }
            //     buf.write_u8(bytes.len() as u8);
            //     buf.write_bytes(bytes);
            // }
            // RData::MX {
            //     preference,
            //     exchange,
            // } => {
            //     buf.write_u16(*preference);
            //     buf.write_str(exchange);
            // }
            // RData::SOA {
            //     mname,
            //     rname,
            //     serial,
            //     refresh,
            //     retry,
            //     expire,
            //     minimum,
            // } => {
            //     buf.write_str(mname);
            //     buf.write_str(rname);
            //     buf.write_u32(*serial);
            //     buf.write_u32(*refresh);
            //     buf.write_u32(*retry);
            //     buf.write_u32(*expire);
            //     buf.write_u32(*minimum);
            // }
            RData::EMPTY(data) => {
                buf.write_bytes(data);
            }
        }

        Ok(buf.into_inner())
    }

    /// Decodes a full DNS message from the given buffer.
    pub fn decode(buf: &mut DnsReadBuffer) -> Result<Dns, DnsError> {
        let id        = buf.read_u16().map_err(|_| DnsError::InvalidField)?;
        let flags_raw = buf.read_u16().map_err(|_| DnsError::InvalidField)?;
        let qd_count  = buf.read_u16().map_err(|_| DnsError::InvalidField)?;
        let an_count  = buf.read_u16().map_err(|_| DnsError::InvalidField)?;
        let ns_count  = buf.read_u16().map_err(|_| DnsError::InvalidField)?;
        let ar_count  = buf.read_u16().map_err(|_| DnsError::InvalidField)?;

        let flags                   = Self::decode_flags(flags_raw);
        let questions    = Self::decode_questions(buf, qd_count)?;
        let answers     = Self::decode_answers(buf, an_count)?;
        let authorities = Self::decode_answers(buf, ns_count)?;
        let additionals = Self::decode_answers(buf, ar_count)?;

        Ok(Dns {
            header: Header {
                id,
                flags,
                qd_count,
                an_count,
                ns_count,
                ar_count,
            },
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    /// Encodes this DNS struct into a buffer suitable for transmission.
    pub fn encode(&self) -> Result<DnsWriteBuffer, DnsError> {
        let mut buffer = DnsWriteBuffer::new();

        let flags = Self::encode_flags(&self.header.flags);

        buffer.write_u16(self.header.id);
        buffer.write_u16(flags);
        buffer.write_u16(self.header.qd_count);
        buffer.write_u16(self.header.an_count);
        buffer.write_u16(self.header.ns_count);
        buffer.write_u16(self.header.ar_count);

        for q in &self.questions {
            buffer.write_str(&q.qname);
            buffer.write_u16(q.qtype);
            buffer.write_u16(q.qclass);
        }

        Self::encode_answers(&mut buffer, &self.answers)?;
        Self::encode_answers(&mut buffer, &self.authorities)?;
        Self::encode_answers(&mut buffer, &self.additionals)?;

        Ok(buffer)
    }

    /// Constructs a new `Dns` instance from all components.
    pub fn new(
        id:    u16,
        flags: Flags,
        qd_count: u16,
        an_count: u16,
        ns_count: u16,
        ar_count: u16,
        questions:   Vec<QueryRecord>,
        answers:     Vec<AnswerRecord>,
        authorities: Vec<AnswerRecord>,
        additionals: Vec<AnswerRecord>,
    ) -> Self {
        Dns {
            header: Header {
                id,
                flags,
                qd_count,
                an_count,
                ns_count,
                ar_count,
            },
            questions,
            answers,
            authorities,
            additionals,
        }
    }

    /// Creates a new DNS IPv4 query for the given domain and ID.
    pub fn new_a_question(domain: &str, id: u16) -> Self {
        let flags = Flags {
            qr:     false,
            opcode: 0,
            aa:     false,
            tc:     false,
            rd:     false,
            ra:     false,
            z:      0,
            rcode:  0,
        };

        let qd_count     = 1;
        let an_count     = 0;
        let ns_count     = 0;
        let ar_count     = 0;
        let questions     = vec![QueryRecord::new(domain.to_string(), 1, 1)];
        let answers      = Vec::new();
        let authorities  = Vec::new();
        let additionals  = Vec::new();

        Dns::new(
            id,
            flags,
            qd_count,
            an_count,
            ns_count,
            ar_count,
            questions,
            answers,
            authorities,
            additionals,
        )
    }

}

impl QueryRecord {
    /// Creates a new query record with the given name, type, and class.
    pub fn new(qname: String, qtype: u16, qclass: u16) -> Self {
        QueryRecord { qname, qtype, qclass }
    }
}

impl AnswerRecord {
    /// Creates a new answer record from rdata
    pub fn new(name: String, rdata: RData) -> Self {
        let atype = match &rdata {
            RData::A(_)     => Type::A     as u16,
            RData::AAAA(_)  => Type::AAAA  as u16,
            RData::CNAME(_) => Type::CNAME as u16,
            RData::NS(_)    => Type::NS  as u16,
            // RData::TXT(_)   => Type::TXT as u16,
            // RData::MX {..}  => Type::MX  as u16,
            // RData::SOA {..} => Type::SOA as u16,
            // RData::PTR(_)   => Type::PTR as u16,
            RData::EMPTY(_) => 0, // or some fallback
        };

        AnswerRecord { 
            aname:  name,
            atype:  atype,
            aclass: 1,        // 1 = IN (Internet)
            ttl:    300,      // Default TTL
            length: rdata.len(),
            rdata:  rdata,
        } 
    }
}