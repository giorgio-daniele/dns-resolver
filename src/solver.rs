use std::net::SocketAddr;
use tokio::net::UdpSocket;
use crate::dns::{Answer, Buffer, Dns, DnsError, RData};

pub async fn proc(dns: Dns, addr: SocketAddr) -> Result<(), DnsError> {
    // Make the request mutable
    let mut dns = dns;

    // Set RD (Recursion Desired) to false
    dns.header.flags.rd = false;

    // Add EDNS0 OPT record to support larger UDP payloads
    dns.add_additional(Answer {
        aname:  String::new(),              // root domain (empty)
        atype:  41,                         // OPT type
        aclass: 4096,                       // UDP payload size
        ttl:    0,                          // Extended RCODE and flags usually zero
        length: 0,                          // No data in RDATA for basic OPT record
        rdata:  RData::EMPTY([]),           // empty rdata
    });

    // Generate a socket and send data
    let data = dns.encode().data;

    // Generate the socket
    let sock = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|_| 
            DnsError::SocketError)?;

    // Send the data to one roo
    sock.send_to(&data, "198.41.0.4:53")
        .await
        .map_err(|_| 
            DnsError::IOError(
                String::from("can't send dns packet to root")))?;

    let mut buf = [0u8; 4096];
    // Read from the socket
    let (size, _) = sock.recv_from(&mut buf)
        .await
        .map_err(|_| 
            DnsError::IOError(
                String::from("can't read dns packet from root")))?;


    let res = Dns::decode(&mut Buffer::new(buf[..size].to_vec()))?;

    for answer in res.additionals {
        println!("NAME={} CLASS={} TYPE={} RDATA={:?}", 
            answer.aname,
            answer.aclass, 
            answer.atype, 
            answer.rdata);
    }

    // for answer in res.authorities {

    //     println!("NAME={} CLASS={} TYPE={} RDATA={:?}", 
    //         answer.aname,
    //         answer.aclass, 
    //         answer.atype, 
    //         answer.rdata);
    // }

    // for item in dns.additionals {
    //     println!("NAME={} CLASS={} TYPE={}", item.aname, item.aclass, item.atype)
    // }

    // // You can then decode or process the response here if needed
    // println!("{:#?}", Dns::decode(&mut Buffer::new(buf.to_vec())));


    Ok(())
}
