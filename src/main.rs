use dns::{Buffer, Dns, DnsError};
use solver::proc;
use tokio::
    net::UdpSocket;

mod dns;
mod solver;

#[tokio::main]
async fn main() -> Result<(), DnsError> {

    // Define a new socket on which the server is going to listen
    // at incoming data
    let sock = UdpSocket::bind("127.0.0.1:8888")
        .await
        .map_err(|_| 
            DnsError::SocketError)?;

    let mut buf = [0u8; 4096];

    loop {
        // Read from the socket
        let (size, addr) = sock.recv_from(&mut buf)
            .await
            .map_err(|_| 
                DnsError::IOError(
                    String::from("can't read dns packet from client")))?;

        // Genereate the DNS message and pass it to 
        // the handler. The handler will be executed
        // within a coroutine in tokio context
        if let Ok(dns) = Dns::decode( &mut Buffer::new(buf[..size].to_vec())) {
            tokio::spawn(proc(dns, addr));
        }
    }
}


// #[cfg(test)]
// mod tests {
//     use crate::dns::{Buffer, Dns};

//     #[test]
//     fn test_uncompressed_qname() {
//         // DNS Header: 12 bytes (randomly filled)
//         // QNAME: 3 (www), 7 (example), 3 (com), 0
//         // QTYPE: 1 (A), QCLASS: 1 (IN)
//         let raw = vec![
//             0x00, 0x01,  // ID
//             0x01, 0x00,  // Flags
//             0x00, 0x01,  // QDCOUNT
//             0x00, 0x00,  // ANCOUNT
//             0x00, 0x00,  // NSCOUNT
//             0x00, 0x00,  // ARCOUNT
//             0x03, b'w', b'w', b'w',
//             0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
//             0x03, b'c', b'o', b'm',
//             0x00,
//             0x00, 0x01,  // QTYPE A
//             0x00, 0x01   // QCLASS IN
//         ];

//         let mut buffer = Buffer::new(raw);
//         let dns = Dns::decode(&mut buffer).unwrap();

//         assert_eq!(dns.header.qd_count, 1);
//         assert_eq!(dns.questions.len(), 1);
//         assert_eq!(dns.questions[0].qname, "www.example.com");
//         assert_eq!(dns.questions[0].qtype, 1);
//         assert_eq!(dns.questions[0].qclass, 1);
//     }

//     #[test]
//     fn test_compressed_qname() {
//         // Question: www.example.com
//         // Answer: pointer to offset 12 (start of www.example.com)
//         let raw = vec![
//             0x00, 0x02,  // ID
//             0x81, 0x80,  // Flags
//             0x00, 0x01,  // QDCOUNT
//             0x00, 0x01,  // ANCOUNT
//             0x00, 0x00,  // NSCOUNT
//             0x00, 0x00,  // ARCOUNT

//             // QNAME: www.example.com
//             0x03, b'w', b'w', b'w',
//             0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
//             0x03, b'c', b'o', b'm',
//             0x00,
//             0x00, 0x01,  // QTYPE A
//             0x00, 0x01,  // QCLASS IN

//             // ANAME (compressed): pointer to offset 12
//             0xC0, 0x0C,
//             0x00, 0x01,  // TYPE A
//             0x00, 0x01,  // CLASS IN
//             0x00, 0x00, 0x00, 0x3C,  // TTL
//             0x00, 0x04,  // RDLENGTH
//             0x5D, 0xB8, 0xD8, 0x22   // RDATA: 93.184.216.34
//         ];

//         let mut buffer = Buffer::new(raw);
//         let dns = Dns::decode(&mut buffer).unwrap();

//         assert_eq!(dns.questions[0].qname, "www.example.com");
//         assert_eq!(dns.answers[0].aname, "www.example.com");
//         assert_eq!(dns.answers[0].rdata, vec![0x5D, 0xB8, 0xD8, 0x22]);
//     }

//     #[test]
//     fn test_buffer_read_bounds() {
//         let mut buffer = Buffer::new(vec![1, 2, 3]);

//         assert_eq!(buffer.read_u8().unwrap(), 1);
//         assert_eq!(buffer.read_u8().unwrap(), 2);
//         assert_eq!(buffer.read_u8().unwrap(), 3);
//         assert!(buffer.read_u8().is_err()); // Exceeds
//     }

//     #[test]
//     fn test_read_string_invalid_utf8() {
//         // Length byte = 1, invalid utf8: 0xFF
//         let mut buffer = Buffer::new(vec![1, 0xFF, 0]);
//         assert!(buffer.read_string().is_err());
//     }
// }
