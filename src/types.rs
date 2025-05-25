use core::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// DNS message header.
///
/// Contains fields identifying the message and counts of question,
/// answer, authority, and additional records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Message identifier.
    pub id: u16,
    /// DNS header flags.
    pub flags: Flags,
    /// Number of entries in the question section.
    pub qd_count: u16,
    /// Number of resource records in the answer section.
    pub an_count: u16,
    /// Number of name server resource records in the authority section.
    pub ns_count: u16,
    /// Number of resource records in the additional section.
    pub ar_count: u16,
}

/// Bitfield flags in a DNS header.
///
/// Includes standard DNS header flags such as QR, Opcode, AA, TC, RD, RA, Z, and RCODE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flags {
    /// Query/Response flag.
    pub qr: bool,
    /// Operation code.
    pub opcode: u8,
    /// Authoritative Answer flag.
    pub aa: bool,
    /// Truncation flag.
    pub tc: bool,
    /// Recursion Desired flag.
    pub rd: bool,
    /// Recursion Available flag.
    pub ra: bool,
    /// Reserved for future use.
    pub z: u8,
    /// Response code.
    pub rcode: u8,
}

/// A DNS question entry.
///
/// Represents a single DNS query with name, type, and class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryRecord {
    /// Domain name being queried.
    pub qname: String,
    /// Query type (e.g., A, AAAA, NS).
    pub qtype: u16,
    /// Query class (usually IN for internet).
    pub qclass: u16,
}

/// Resource data variants.
///
/// Holds data for different DNS resource record types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    NS(String),
    CNAME(String),
    TXT(String),
    MX {
        preference: u16,
        exchange:   String,
    },
    SOA {
        mname:   String,
        rname:   String,
        serial:  u32,
        refresh: u32,
        retry:   u32,
        expire:  u32,
        minimum: u32,
    },
    PTR(String),
    EMPTY([u8; 0]), // Generic fallback
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Type {
    A     = 1,
    NS    = 2,
    CNAME = 5,
    MX    = 15,
    TXT   = 16,
    AAAA  = 28,
    PTR   = 12,
    SOA   = 6,
}

impl Type {
    pub fn from_u16(value: u16) -> Option<Type> {
        match value {
            1  => Some(Type::A),
            2  => Some(Type::NS),
            5  => Some(Type::CNAME),
            6  => Some(Type::SOA),
            12 => Some(Type::PTR),
            15 => Some(Type::MX),
            16 => Some(Type::TXT),
            28 => Some(Type::AAAA),
            _  => None,
        }
    }
}

impl RData {
    /// Returns the length in bytes of the RData payload.
    ///
    /// For `A` and `AAAA` records, this is fixed.
    /// For domain name records like `CNAME` and `NS`, length includes 
    /// label length plus 2 bytes.
    /// For other variants, returns 0.
    pub fn len(&self) -> u16 {
        match self {
            RData::A(_)              => 4,
            RData::AAAA(_)           => 16,
            RData::CNAME(s) => s.len() as u16 + 2,
            RData::NS(s)    => s.len() as u16 + 2,
            _                        => 0,
        }
    }

    /// Returns the contained IPv4 address if the record is an `A` record.
    ///
    /// # Examples
    ///
    /// ```
    /// if let Some(ipv4) = rdata.as_a() {
    ///     println!("IPv4 address: {}", ipv4);
    /// }
    /// ```
    pub fn as_a(&self) -> Option<Ipv4Addr> {
        if let RData::A(ip) = self {
            Some(*ip)
        } else {
            None
        }
    }

    /// Returns the contained IPv6 address if the record is an `AAAA` record.
    ///
    /// # Examples
    ///
    /// ```
    /// if let Some(ipv6) = rdata.as_aaaa() {
    ///     println!("IPv6 address: {}", ipv6);
    /// }
    /// ```
    pub fn as_aaaa(&self) -> Option<std::net::Ipv6Addr> {
        if let RData::AAAA(ipv6) = self {
            Some(*ipv6)
        } else {
            None
        }
    }

    /// Returns the contained domain name if the record is an `NS` (name server) record.
    ///
    /// # Examples
    ///
    /// ```
    /// if let Some(ns_name) = rdata.as_ns() {
    ///     println!("Name server domain: {}", ns_name);
    /// }
    /// ```
    pub fn as_ns(&self) -> Option<&str> {
        if let RData::NS(name) = self {
            Some(name)
        } else {
            None
        }
    }

     /// Returns the contained domain name if the record is an `CNAME` (name server) record.
    ///
    /// # Examples
    ///
    /// ```
    /// if let Some(cname) = rdata.as_cname() {
    ///     println!("Cnanonical server name: {}", cname);
    /// }
    /// ```
    pub fn as_cname(&self) -> Option<&str> {
        if let RData::CNAME(name) = self {
            Some(name)
        } else {
            None
        }
    }   
}


/// A DNS answer record.
///
/// Represents a resource record in an answer, authority, or additional section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnswerRecord {
    /// Domain name this record pertains to.
    pub aname: String,
    /// Type of the record.
    pub atype: u16,
    /// Class of the record.
    pub aclass: u16,
    /// Time to live (in seconds).
    pub ttl: u32,
    /// Length of the resource data.
    pub length: u16,
    /// Resource data payload.
    pub rdata: RData,
}

/// A parsed DNS message.
///
/// Contains the header, question, answer, authority, and additional sections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dns {
    /// DNS message header.
    pub header: Header,
    /// Vector of question records.
    pub questions: Vec<QueryRecord>,
    /// Vector of answer records.
    pub answers: Vec<AnswerRecord>,
    /// Vector of authority records.
    pub authorities: Vec<AnswerRecord>,
    /// Vector of additional records.
    pub additionals: Vec<AnswerRecord>,
}

/// DNS parsing or encoding errors.
#[derive(Debug)]
pub enum DnsError {
    /// Invalid field value encountered.
    InvalidField,
    /// Invalid resource data encountered.
    InvalidRData,
    /// Socket-related error.
    SocketError,
    /// Generic I/O error with message.
    IOError(String),
}

/// A read-only buffer wrapper for parsing DNS messages.
///
/// Holds a byte slice and current read offset.
/// Supports zero-copy reading of primitives and DNS names with compression pointers.
#[derive(Debug)]
pub struct DnsReadBuffer<'a> {
    /// Underlying data slice to read from.
    pub data: &'a [u8],
    /// Current read offset index into `data`.
    pub index: usize,
}

/// Errors that can occur during reading from a DNS buffer.
#[derive(Debug)]
pub enum DnsBufferError {
    /// Reached end of buffer unexpectedly.
    EndOfBuffer,
    /// Encountered invalid string (e.g., invalid UTF-8 or pointers).
    InvalidString,
    /// DNS label exceeded maximum length.
    LabelTooLong,
}

/// A write-only buffer for constructing DNS messages.
///
/// Holds a growable vector of bytes to which data can be appended.
#[derive(Debug)]
pub struct DnsWriteBuffer {
    /// Internal data buffer.
    pub data: Vec<u8>,
}
