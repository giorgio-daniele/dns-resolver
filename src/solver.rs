use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use crate::dns::{AnswerRecord, Buffer, Dns, DnsError, RData};

async fn send_recv(
    msg: &[u8],
    addr: &str,
) -> Result<([u8; 4096], usize), DnsError> {
    /*
     * Create an ephemeral UDP socket, send DNS packet to remote addr,
     * await response, and return the received buffer and size.
     */
    let sock = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|_| DnsError::SocketError)?;

    sock.send_to(msg, format!("{}", addr))
        .await
        .map_err(|_| DnsError::IOError(String::from("can't send DNS packet")))?;

    let mut buf = [0u8; 4096];
    let (size, _src) = sock.recv_from(&mut buf)
        .await
        .map_err(|_| DnsError::IOError(String::from("can't read DNS packet")))?;

    Ok((buf, size))
}

fn process_records(map: &mut HashMap<String, Vec<RData>>, records: &Vec<AnswerRecord>) {
    for a in records {
        map
            .entry(a.aname.clone())
            .and_modify(|v| v.push(a.rdata.clone()))
            .or_insert_with(|| vec![a.rdata.clone()]);
    }
}

pub async fn proc(mut dns: Dns, addr: SocketAddr) -> Result<Vec<u8>, DnsError> {
    /*
     * Send request to root server with EDNS0 and recursion disabled.
     * Collect authoritative and additional records.
     * Query the first resolved A record from additional records.
     */
    dns.header.flags.rd = false;

    /*
     * Root server response storage
     * 
     * - root_answers: Typically empty, root servers rarely return direct answers.
     * - root_authorities: Maps queried domain (e.g., "com") to name servers 
     *   responsible for that TLD.
     * - root_additionals: Maps those name servers to their corresponding IP 
     *   addresses.
     */
    let mut _root_answers    : HashMap<String, Vec<RData>> = HashMap::new();
    let mut root_authorities : HashMap<String, Vec<RData>> = HashMap::new();
    let mut root_additionals : HashMap<String, Vec<RData>> = HashMap::new();

    /*
     * TLD server response storage
     * 
     * - tld_answers: Usually empty, TLD servers also delegate to authoritative 
     *   servers.
     * - tld_authorities: Maps domain (e.g., "example.com") to authoritative 
     *   name servers.
     * - tld_additionals: Maps those name servers to their IP addresses.
     */
    let mut _tld_answers    : HashMap<String, Vec<RData>> = HashMap::new();
    let mut tld_authorities : HashMap<String, Vec<RData>> = HashMap::new();
    let mut tld_additionals : HashMap<String, Vec<RData>> = HashMap::new();

    /*
     * Authoritative server response storage
     * 
     * - auth_answers: Contains the final answer(s), such as A/AAAA or CNAME 
     *   records.
     * - auth_authorities: May include SOA (Start of Authority) or further 
     *   delegation data.
     * - auth_additionals: Related additional records (e.g., A records of 
     *   NS entries).
     */
    let mut auth_answers     : HashMap<String, Vec<RData>> = HashMap::new();
    let mut auth_authorities : HashMap<String, Vec<RData>> = HashMap::new();
    let mut auth_additionals : HashMap<String, Vec<RData>> = HashMap::new();

    // Add EDNS0 OPT record to support larger UDP payloads
    dns.add_additional(AnswerRecord {
        aname:  String::new(),  // root domain
        atype:  41,             // OPT
        aclass: 4096,           // UDP payload size
        ttl:    0,              // extended flags
        length: 0,              // no RDATA
        rdata:  RData::EMPTY([]),
    });

    /*
     * 
     * 
     * Query the ROOT Server
     * 
     * 
     */
    let msg        = dns.encode()?;
    let (res, len) = send_recv(msg.get_data(), "198.41.0.4:53").await?;
    let resp       = Dns::decode(&mut Buffer::new(res[..len].to_vec()))?;

    // Fill the maps associated to root reply
    process_records(& mut root_authorities, &resp.authorities);
    process_records(& mut root_additionals, &resp.additionals);

    let addr = 
        root_additionals
        .iter()
        .find_map(|(_, values)| {
            values.iter().find_map(|r| {
                if let RData::A(ipv4) = r {
                    Some(ipv4.to_string() + ":53")
                } else {
                    None
                }
        })
    })
        .ok_or_else(|| 
            DnsError::IOError(String::from("no A record found in additional records")))?;
    /*
     * 
     * 
     * Query the TLD Server
     * 
     * 
     */
    let msg        = dns.encode()?;
    let (res, len) = send_recv(msg.get_data(), &addr).await?;
    let resp       = Dns::decode(&mut Buffer::new(res[..len].to_vec()))?;
    
    // Fill the maps associated to tld reply
    process_records(& mut tld_authorities, &resp.authorities);
    process_records(& mut tld_additionals, &resp.additionals);

    /*
     * 
     * 
     * Query the Authoritative Server
     * 
     * 
     */
    let addr = 
        tld_additionals
        .iter()
        .find_map(|(_, values)| {
            values.iter().find_map(|r| {
                if let RData::A(ipv4) = r {
                    Some(ipv4.to_string() + ":53")
                } else {
                    None
                }
        })
    })
        .ok_or_else(|| 
            DnsError::IOError(String::from("no A record found in additional records")))?;

    let msg        = dns.encode()?;
    let (res, len) = send_recv(msg.get_data(), &addr).await?;
    let resp       = Dns::decode(&mut Buffer::new(res[..len].to_vec()))?;

    process_records(& mut auth_answers,     &resp.answers);
    process_records(& mut auth_authorities, &resp.authorities);
    process_records(& mut auth_additionals, &resp.additionals);    

    // println!("{:#?}", resp.answers);
    // println!("-----------");
    // println!("{:#?}", auth_authorities);
    // println!("-----------");
    // println!("{:#?}", auth_additionals);
    // println!("-----------");
    // println!("-----------");

    // Finalize and send DNS response to client
    // Mark as response
    dns.header.flags.qr    = true;
    dns.header.flags.aa    = true;   // Authoritative if final server was authoritative
    dns.header.flags.ra    = false;  // No recursion
    dns.header.flags.rcode = 0;      // No error

    // Copy answer sections from final resolved response
    dns.answers     = resp.answers.clone();
    dns.authorities = resp.authorities.clone();
    dns.additionals = resp.additionals.clone();

    // Update section counts
    dns.header.an_count = dns.answers.len()     as u16;
    dns.header.ns_count = dns.authorities.len() as u16;
    dns.header.ar_count = dns.additionals.len() as u16;

    println!("-----------");
    println!("{:#?}", dns);
    println!("-----------");

    let resp = dns.encode()?;
    return Ok(resp.get_data().to_vec());
}
