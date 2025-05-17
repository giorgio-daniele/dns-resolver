use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use crate::dns::{AnswerRecord, Buffer, Dns, DnsError, RData};

async fn send_recv(
    msg: &[u8],
    addr: &str,
    port: u16,
) -> Result<([u8; 4096], usize), DnsError> {
    /*
     * Create an ephemeral UDP socket, send DNS packet to remote addr,
     * await response, and return the received buffer and size.
     */
    let sock = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|_| DnsError::SocketError)?;

    sock.send_to(msg, format!("{}:{}", addr, port))
        .await
        .map_err(|_| DnsError::IOError(String::from("can't send DNS packet")))?;

    let mut buf = [0u8; 4096];
    let (size, _src) = sock.recv_from(&mut buf)
        .await
        .map_err(|_| DnsError::IOError(String::from("can't read DNS packet")))?;

    Ok((buf, size))
}

pub async fn proc(mut dns: Dns, _addr: SocketAddr) -> Result<(), DnsError> {
    /*
     * Send request to root server with EDNS0 and recursion disabled.
     * Collect authoritative and additional records.
     * Query the first resolved A record from additional records.
     */

    dns.header.flags.rd = false;

    // Two maps: domain -> authoritative RData, and name server -> A record(s)
    let mut root_domains   : HashMap<String, Vec<RData>> = HashMap::new();
    let mut root_addresses : HashMap<String, Vec<RData>> = HashMap::new();

    // Two maps: domain -> authoritative RData, and name server -> A record(s)
    let mut tld_domains   : HashMap<String, Vec<RData>> = HashMap::new();
    let mut tld_addresses : HashMap<String, Vec<RData>> = HashMap::new();

    // Add EDNS0 OPT record to support larger UDP payloads
    dns.add_additional(AnswerRecord {
        aname:  String::new(),  // root domain
        atype:  41,             // OPT
        aclass: 4096,           // UDP payload size
        ttl:    0,              // extended flags
        length: 0,              // no RDATA
        rdata:  RData::EMPTY([]),
    });

    // Initial query to root server
    let msg       = dns.encode()?;
    let (res, len) = send_recv(msg.get_data(), "198.41.0.4", 53).await?;
    let resp         = Dns::decode(&mut Buffer::new(res[..len].to_vec()))?;

    /*
     * 
     * If "answers" is empty (to be expected), it means the server does not
     * anything about the domain mapping, but it knows the servers which are
     * responsible for mapping.... As a consequence, if "answers" records is
     * no longer empty, it means... the process is done!
     *
     */

    for a in &resp.authorities {
        root_domains
            .entry(a.aname.clone())
            .and_modify(|v| v.push(a.rdata.clone()))
            .or_insert_with(|| vec![a.rdata.clone()]);
    }

    for a in resp.additionals.iter().filter(|a| matches!(a.rdata, RData::A(_))) {
        root_addresses
            .entry(a.aname.clone())
            .and_modify(|v| v.push(a.rdata.clone()))
            .or_insert_with(|| vec![a.rdata.clone()]);
    }

    // Choose the first available A record from additional records
    let mut addr = None;
    let port = 53;

    if let Some((_key, values)) = root_addresses.iter().next() {
        if let Some(RData::A(ipv4)) = values.iter().find(|r| matches!(r, RData::A(_))) {
            addr = Some(ipv4.to_string());
        }
    }

    let addr = addr.ok_or_else(|| DnsError::IOError(
        String::from("no A record found in additional records")))?;

    // Send follow-up request (query the TLD) to the resolved IP address
    let msg       = dns.encode()?;
    let (res, len) = send_recv(msg.get_data(), &addr, port).await?;
    let resp         = Dns::decode(&mut Buffer::new(res[..len].to_vec()))?;


    for a in &resp.authorities {
        tld_domains
            .entry(a.aname.clone())
            .and_modify(|v| v.push(a.rdata.clone()))
            .or_insert_with(|| vec![a.rdata.clone()]);
    }

    for a in resp.additionals.iter().filter(|a| matches!(a.rdata, RData::A(_))) {
        tld_addresses
            .entry(a.aname.clone())
            .and_modify(|v| v.push(a.rdata.clone()))
            .or_insert_with(|| vec![a.rdata.clone()]);
    }

    // println!("Updated addresses after TLD query:\n{:#?}", addresses);

    /*
     * 
     * If "answers" is empty (to be expected), it means the server does not
     * anything about the domain mapping, but it knows the servers which are
     * responsible for mapping.... As a consequence, if "answers" records is
     * no longer empty, it means... the process is done!
     * 
     * Next stage should be the last one...
     *
     */

    // Choose the first available A record from additional records
    let mut addr = None;
    let port = 53;

    if let Some((_key, values)) = tld_addresses.iter().next() {
        if let Some(RData::A(ipv4)) = values.iter().find(|r| matches!(r, RData::A(_))) {
            addr = Some(ipv4.to_string());
        }
    }

    let addr = addr.ok_or_else(|| DnsError::IOError(
        String::from("no A record found in additional records")))?;

    println!("{:#?}", tld_addresses);

    println!("________________________");

    // Send follow-up request (query the TLD) to the resolved IP address
    let msg       = dns.encode()?;
    let (res, len) = send_recv(msg.get_data(), &addr, port).await?;
    let resp         = Dns::decode(&mut Buffer::new(res[..len].to_vec()))?;

    println!("{:#?}", resp);


    Ok(())
}
