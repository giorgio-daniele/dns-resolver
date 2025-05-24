use crate::{
    contact,
    types::{Dns, DnsError, DnsReadBuffer, RData, Type},
};
use async_recursion::async_recursion;
use std::{collections::HashSet, net::Ipv4Addr};

#[async_recursion]
pub async fn resolve(
    domain:  &str,
    address: &str,
    depth:   usize,
) -> Result<Vec<RData>, DnsError> {


   println!(" depth={}, server={}, domain={}", depth, address, domain);

    if depth == 0 {
        return Err(DnsError::IOError("max recursion depth reached".into()));
    }

    /*
     * 
     * Generate a new DNS query, asking the "address" the IPv4 address
     * associated with the "domain". Once the query is issued, await 
     * for the response... At the end, decode the buffer, making it into
     * a DNs reply
     * 
     */

    let mut buffer = [0u8; 4096];
    let dns = Dns::new_ipv4_query(domain, 0x1234);
    contact::contact(&dns.encode()?.data, &format!("{}:53", address), &mut buffer).await?;
    let dns = Dns::decode(&mut DnsReadBuffer::new(&buffer))?;

    /*
     * 
     * Inspect the answers
     * 
     */

    let mut records   = vec![];
    let mut cname = None;

    for answer in &dns.answers {
        match &answer.rdata {
            RData::A(ip) => {
                println!("\tFound A record: {} -> {}", answer.aname, ip);
                records.push(RData::A(*ip));
            },
            RData::AAAA(ip) => {
                println!("\tFound AAAA record: {} -> {}", answer.aname, ip);
                records.push(RData::AAAA(*ip));
            }
            RData::CNAME(name) => {
                println!("\tFound CNAME: {} -> {}", answer.aname, name);
                cname = Some(name.to_owned());
            }
            _ => {}
        }
    }

    /*
     * 
     * Inspect the answers: if the records are not empty, 
     * the return the result. It will contains the IPv4/IPv6 
     * addresses associated with the "domain" that the invoker 
     * is looking for
     * 
     */

    if !records.is_empty() {
        return Ok(records);
    }

    /*
     * 
     * Sometimes, you no have any IPv4/IPv6 address, but you
     * have the canonical name... The DNS is telling you: if
     * you want the IPv4/IPv6 address of such domain, you have
     * to lookup for the canonical name, which means not the
     * synonym.
     * 
     */


    if let Some(cname) = cname {
        return resolve(&cname, address, depth - 1).await;
    }

    
    /*
     * 
     * 
     * Extract the authorities (we haven't reached the end of the
     * hierarchy).
     * 
     * 
     */

    let domains: Vec<String> = dns.authorities.iter().filter_map(|auth| {
        if Type::from_u16(auth.atype) == Some(Type::NS) {
            if let RData::NS(ns) = &auth.rdata {
                println!("\tfound NS record: {} -> {}", auth.aname, ns);
                Some(ns.clone())
            } else { None }
        } else { None }
    }).collect();
    //println!();

    /*
     * 
     * 
     * Find in the additional record, the glue records: the IPv4/IPv6 addresses
     * matching the name servers in the authority section
     * 
     * 
     */
    let addresses: Vec<Ipv4Addr> = dns.additionals.iter().filter_map(|add| {
        if Type::from_u16(add.atype) == Some(Type::A) {
            if let RData::A(ip) = &add.rdata {
                println!("\t\tfound glue A record: {} -> {}", add.aname, ip);
                Some(*ip)
            } else { None }
        } else { None }
    }).collect();
    //println!();

    /*
     * 
     * 
     * For each glue record, select the first as it comes and recursively
     * invoke the function to resolve the original address to next name
     * server (using the IPv4/IPv6 address).
     * 
     * 
     */

    for ip in addresses {
            if let Ok(records) = resolve(domain, &ip.to_string(), depth - 1).await {
                if !records.is_empty() {
                    return Ok(records);
                }
            }
    }

    /*
     * 
     * 
     * If no glue records are found, the code should resolve the IP address
     * of each name server (or at least the first one).
     * 
     * 
     */

    for ns in domains {
            let root = "198.41.0.4"; // a.root-servers.net
            if let Ok(addresses) = resolve(&ns, root, depth - 1).await {
                for address in addresses {
                    if let RData::A(ip) = address {
                            if let Ok(records) = resolve(domain, &ip.to_string(), depth - 1).await {
                                if !records.is_empty() {
                                    return Ok(records);
                                }
                            }
                    }
                }
            }
    }

    Err(DnsError::IOError("No valid answer found".into()))
}
