mod buffer;
mod contact;
mod dns;
mod resolver;
mod types;

use resolver::resolve;
use std::{collections::HashSet, net::SocketAddr, sync::Arc};
use tokio::{net::UdpSocket, sync::Mutex};
use types::{AnswerRecord, Dns, DnsError, DnsReadBuffer, RData, Type};

const ROOT_SERVER: &str = "198.41.0.4";
const MAX_DEPTH: usize = 20;

#[tokio::main]
async fn main() -> Result<(), DnsError> {
    let socket = Arc::new(Mutex::new(
        UdpSocket::bind("127.0.0.1:53")
            .await
            .map_err(|_| DnsError::SocketError)?,
    ));

    println!("DNS server listening on 127.0.0.1:53");
    let mut buf = [0u8; 4096];

    loop {
        let (len, client) = socket
            .lock()
            .await
            .recv_from(&mut buf)
            .await
            .map_err(|_| DnsError::SocketError)?;
        let socket = Arc::clone(&socket);
        let data = buf[..len].to_vec();

        tokio::spawn(async move {
            if let Err(e) = handle_request(socket, client, data).await {
                eprintln!("Error handling request from {}: {:?}", client, e);
            }
        });
    }
}

async fn handle_request(
    socket: Arc<Mutex<UdpSocket>>,
    client: SocketAddr,
    buffer: Vec<u8>,
) -> Result<(), DnsError> {


    let req = Dns::decode(&mut DnsReadBuffer::new(&buffer))?;
    let dns = req
        .questions
        .first()
        .ok_or_else(|| DnsError::IOError("No question in request".into()))?;

    let answers = resolve(&dns.qname, ROOT_SERVER, MAX_DEPTH).await?;


    println!("{:?}", answers);

    // Generate the result
    let mut res = req.clone();
    res.header.flags.qr = true;                     // Mark as response
    res.header.flags.rd = req.header.flags.rd;      // Copy Recursion Desired
    res.header.flags.ra = true;                     // Recursion Available
    res.header.flags.z  = 0;
    res.answers.clear();

    if !answers.is_empty() {
        res.header.flags.rcode = 0; // No error
        res.header.an_count    = answers.len() as u16;
        res.answers            = answers
                .into_iter()
                .map(|rdata| {
                    let atype = match rdata {
                        RData::A(_)       => Type::A     as u16,
                        RData::AAAA(_)    => Type::AAAA  as u16,
                        RData::CNAME(_)   => Type::CNAME as u16,
                        RData::NS(_)      => Type::NS    as u16,
                        RData::MX { .. }  => Type::MX    as u16,
                        RData::TXT(_)     => Type::TXT   as u16,
                        RData::SOA { .. } => Type::SOA   as u16,
                        RData::PTR(_)     => Type::PTR   as u16,
                        RData::EMPTY(_)   => 0,
                    };

                    AnswerRecord {
                        aname:  dns.qname.clone(),
                        atype,
                        aclass: dns.qclass,
                        ttl:    300,
                        length: rdata.record_length(),
                        rdata,
                    }
                })
                .collect();
    } else {
        res.header.flags.rcode = 3; // NXDOMAIN
        res.header.an_count    = 0;
    }


    let enc = res.encode()?;

    println!("\n\n\n");

    println!("{:#?}", req);
    println!();
    println!("{:#?}", res);

    // Send the response
    socket
        .lock()
        .await
        .send_to(&enc.data, client)
        .await
        .map_err(|_| DnsError::SocketError)?;

    Ok(())

}
