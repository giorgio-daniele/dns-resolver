use std::collections::HashMap;
use rand::seq::IndexedRandom;
use tokio::net::UdpSocket;
use crate::dns::{AnswerRecord, Buffer, Dns, DnsError, RData};

async fn send_recv(
    msg:  &[u8],
    addr: &str,
) -> Result<([u8; 4096], usize), DnsError> {
    
    // Create an ephemeral UDP socket, send DNS packet to remote 
    // addr, await response, and return the received buffer and 
    // size.
    let sock = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|_| DnsError::SocketError)?;

    sock.send_to(msg, addr)
        .await
        .map_err(|_| DnsError::IOError(String::from("can't send DNS packet")))?;

    let mut buf = [0u8; 4096];
    let (size, _src) = sock.recv_from(&mut buf)
        .await
        .map_err(|_| DnsError::IOError(String::from("can't read DNS packet")))?;

    Ok((buf, size))
}


fn extract_server_ip(
     additionals: &[AnswerRecord]
) -> Result<(String, String), DnsError> {

    let mut map: HashMap<String, Vec<RData>> = HashMap::new();

    // Generate a map that associates to each
    // server name the list of records that
    // are associated
    for a in additionals {
        map
            .entry(a.aname.clone())
            .and_modify(|v| 
                v.push(a.rdata.clone()))
            .or_insert_with(|| 
                vec![a.rdata.clone()]);
    }

    // Select a server name for which there is a
    // record (of type A) to be used for get an
    // IP address
    map.iter()
        .filter(|(server, _)| 
            !server.is_empty() && server.as_str() != ".")
        .find_map(|(server, records)| {
            records.iter().find_map(|record| {
                if let RData::A(ipv4) = record {
                    Some((server.clone(), format!("{}:53", ipv4)))
                } else {
                    None
                }
            })
        })
        .ok_or_else(|| 
            DnsError::FailedResolution(
                String::from("no IPv4 address found in additionals")))
}


pub async fn resolve_ip(
    dns: &mut Dns,
) -> Result<Vec<u8>, DnsError> {

     // Disable recursion
     dns.header.flags.rd = false;
 
     // Add EDNS0 OPT record for larger UDP payload
     dns.add_additional(AnswerRecord {
         aname:  String::new(),
         atype:  41,    // OPT record type
         aclass: 4096,  // UDP payload size
         ttl:    0,
         length: 0,
         rdata: RData::EMPTY([]),
     });

     let root_servers = [
        "198.41.0.4:53",    // A
        "199.9.14.201:53",  // B
        "192.33.4.12:53",   // C
        "199.7.91.13:53",   // D
        "192.203.230.10:53",// E
        "192.5.5.241:53",   // F
        "192.112.36.4:53",  // G
        "198.97.190.53:53", // H
        "192.36.148.17:53", // I
        "192.58.128.30:53", // J
        "193.0.14.129:53",  // K
        "199.7.83.42:53",   // L
        "202.12.27.33:53",  // M
    ];
    
    
    // Query Root server for TLD NS
    let root_server = {
        let mut rng = rand::rng();
        root_servers.choose(&mut rng).unwrap().to_owned()
    };

    let (resp, len) = send_recv(dns.encode()?.get_data(), root_server).await?;
    let root_reply = Dns::decode(&mut Buffer::new(resp[..len].to_vec()))?;

    // Query TLD server for Authoritative
    let (tld_server_name, tld_server_addr) = extract_server_ip(&root_reply.additionals)?;
    let (resp, len) = send_recv(dns.encode()?.get_data(), &tld_server_addr).await?;
    let tld_reply = Dns::decode(&mut Buffer::new(resp[..len].to_vec()))?;

    // Query TLD server for getting the IP address
    let (auth_server_name, auth_server_addr) = extract_server_ip(&tld_reply.additionals)?;
    let (resp, len) = send_recv(dns.encode()?.get_data(), &auth_server_addr).await?;
    let auth_reply = Dns::decode(&mut Buffer::new(resp[..len].to_vec()))?;

    // Create a fresh DNS response based on initial query, but marking flags accordingly
    dns.header.id          = auth_reply.header.id; // Keep the last server's ID for consistency
    dns.header.flags.qr    = true;
    dns.header.flags.aa    = true;   // authoritative answer
    dns.header.flags.ra    = false;  // no recursion
    dns.header.flags.rcode = 0;      // no error

    // Copy final answer sections
    dns.answers     = auth_reply.answers;
    dns.authorities = auth_reply.authorities;
    dns.additionals = auth_reply.additionals;

    // Update counts
    dns.header.an_count = dns.answers.len() as u16;
    dns.header.ns_count = dns.authorities.len() as u16;
    dns.header.ar_count = dns.additionals.len() as u16;

    // AnswerRecord {
    //     aname: "www.polito.it",
    //     atype: 5,
    //     aclass: 1,
    //     ttl: 3600,
    //     length: 12,
    //     rdata: CNAME(
    //         "webvip-01.polito.it",
    //     ),
    // },

    // for a in &dns.answers {
    //     println!("[DEBUG]: {} {} {} {} {} {}", 
    //         a.aname,
    //         a.atype,
    //         a.aclass,
    //         a.ttl,
    //         a.length,
    //         a.rdata);
    // }
    // println!("\n");


    // Encode and return
    let encoded = dns.encode()?;
    Ok(encoded.get_data().to_vec())
    //Ok([0u8; 1].to_vec())
}
