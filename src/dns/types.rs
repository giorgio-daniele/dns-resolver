/// DNS message header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Unique identifier for the DNS transaction.
    pub id: u16,
    /// Bitfield flags specifying message properties 
    /// (e.g., query/response, recursion desired).
    pub flags: Flags,
    /// Number of questions in the DNS message.
    pub qd_count: u16,
    /// Number of answer records in the DNS message.
    pub an_count: u16,
    /// Number of authority records in the DNS message.
    pub ns_count: u16,
    /// Number of additional records in the DNS message.
    pub ar_count: u16,
}

/// Bitfield flags in a DNS header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flags {
    /// Query/Response flag: `false` = query, `true` = response.
    pub qr: bool,
    /// Operation code: usually 0 (standard query).
    pub opcode: u8,
    /// Authoritative Answer: `true` if the responding 
    /// server is authoritative.
    pub aa: bool,
    /// Truncation: `true` if the message was truncated 
    /// due to size limits.
    pub tc: bool,
    /// Recursion Desired: client asks server to perform 
    /// recursive query.
    pub rd: bool,
    /// Recursion Available: server indicates it supports 
    /// recursion.
    pub ra: bool,
    /// Reserved field (usually zero).
    pub z: u8,
    /// Response code indicating success or error type.
    pub rcode: u8,
}

/// A DNS question entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// Domain name being queried (e.g., "example.com").
    pub qname: String,
    /// Type of query (e.g., A, AAAA, MX).
    pub qtype: u16,
    /// Class of query (typically 1 for IN = Internet).
    pub qclass: u16,
}

/// A DNS answer record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// Domain name to which this answer refers.
    pub aname: String,
    /// Type of the answer (e.g., A, AAAA, MX).
    pub atype: u16,
    /// Class of the answer (typically 1 for IN = Internet).
    pub aclass: u16,
    /// Time-to-live in seconds (how long the result is cacheable).
    pub ttl: u32,
    /// Length of the resource data.
    pub length: u16,
    /// Raw resource data (e.g., IP address in bytes).
    pub rdata: Vec<u8>,
}

/// A parsed DNS message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dns {
    /// Header section of the DNS message.
    pub header:     Header,
    /// List of question entries in the DNS message.
    pub questions: Vec<Question>,
    /// List of answer records in the DNS message.
    pub answers:    Vec<Answer>,
    /// List of authority records in the DNS message.
    pub authorities:   Vec<Answer>,
    /// List of additional record in the DNS message.
    pub additionals:   Vec<Answer>,
}


/// Errors that may occur during buffer operations.
#[derive(Debug)]
pub enum DnsError {
    EndOfBuffer,
    SocketError,
    IOError(String),
    UnsupportedRecordType
}


use std::fmt::{self, Display, Formatter};

impl Display for Flags {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "    {:<7}= {}", "qr",     self.qr)?;
        writeln!(f, "    {:<7}= {}", "opcode", self.opcode)?;
        writeln!(f, "    {:<7}= {}", "aa",     self.aa)?;
        writeln!(f, "    {:<7}= {}", "tc",     self.tc)?;
        writeln!(f, "    {:<7}= {}", "rd",     self.rd)?;
        writeln!(f, "    {:<7}= {}", "ra",     self.ra)?;
        writeln!(f, "    {:<7}= {}", "z",      self.z)?;
        writeln!(f, "    {:<7}= {}", "rcode",  self.rcode)
    }
}

impl Display for Header {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "Header:")?;
        writeln!(f, "  {:<9}= 0x{:04X} ({})", "id", self.id, self.id)?;
        writeln!(f, "  flags")?;
        write!(f, "{}", self.flags)?;
        writeln!(f, "  {:<9}= {}", "qd_count", self.qd_count)?;
        writeln!(f, "  {:<9}= {}", "an_count", self.an_count)?;
        writeln!(f, "  {:<9}= {}", "ns_count", self.ns_count)?;
        writeln!(f, "  {:<9}= {}", "ar_count", self.ar_count)
    }
}

impl Display for Question {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "  - {:<7}= {}", "qname", self.qname)?;
        writeln!(f, "    {:<7}= {}", "qtype", self.qtype)?;
        writeln!(f, "    {:<7}= {}", "qclass", self.qclass)
    }
}

impl Display for Answer {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "  - {:<7}= {}", "aname", self.aname)?;
        writeln!(f, "    {:<7}= {}", "atype", self.atype)?;
        writeln!(f, "    {:<7}= {}", "aclass", self.aclass)?;
        writeln!(f, "    {:<7}= {}", "ttl", self.ttl)?;
        writeln!(f, "    {:<7}= {}", "rdlength", self.length)?;
        write!(f,   "    {:<7}= ", "rdata")?;
        if self.rdata.is_empty() {
            writeln!(f, "<empty>")
        } else {
            for (i, byte) in self.rdata.iter().enumerate() {
                if i > 0 && i % 16 == 0 {
                    writeln!(f)?;
                    write!(f, "              ")?; // Align continuation lines
                }
                write!(f, "{:02X} ", byte)?;
            }
            writeln!(f)
        }
    }
}

impl Display for Dns {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.header)?;
        writeln!(f, "Questions:")?;
        if self.questions.is_empty() {
            writeln!(f, "  <none>")?;
        } else {
            for q in &self.questions {
                write!(f, "{}", q)?;
            }
        }
        writeln!(f, "Answers:")?;
        if self.answers.is_empty() {
            writeln!(f, "  <none>")?;
        } else {
            for a in &self.answers {
                write!(f, "{}", a)?;
            }
        }
        Ok(())
    }
}