use crate::{
    contact,
    types::{AnswerRecord, Dns, DnsError, DnsReadBuffer, RData, Type},
};
use async_recursion::async_recursion;
use std::net::Ipv4Addr;

fn inspect(
    answers: &Vec<AnswerRecord>
) -> (Vec<RData>, 
      Vec<RData>, 
      Vec<RData>) {

    let mut ipv4_addresses = Vec::new();
    let mut ipv6_addresses = Vec::new();
    let mut cnonical_names = Vec::new();

    // Inspect the answers and collect the results
    for answer in answers {
        match &answer.rdata {
            RData::A(addr)     => ipv4_addresses.push(RData::A(*addr)),
            RData::AAAA(addr)  => ipv6_addresses.push(RData::AAAA(*addr)),
            RData::CNAME(name)   => cnonical_names.push(RData::CNAME(name.to_owned())),
            _ => {}
        }
    }

    (ipv4_addresses, ipv6_addresses, cnonical_names)
}

#[async_recursion]
pub async fn resolve(
    domain:  &str,
    address: &str,
    depth:   usize,
) -> Result<(Vec<RData>, 
             Vec<RData>, 
             Vec<RData>), DnsError> {

    if depth == 0 {
        return Err(DnsError::IOError("max recursion depth reached".into()));
    }

    // Generate a brand new buffer, ask the DNS which is the IPv4 
    // address associated to domain passed as argument to the 
    // function. In the end, decode the response into a DNS data 
    // type and inspect the result
    let mut buffer = [0u8; 4096];
    let req = Dns::new_a_question(domain, 0x1234);

    // Request the DNS the response
    contact::contact(&req.encode()?.data, &format!("{}:53", address), &mut buffer).await?;
    let res = Dns::decode(&mut DnsReadBuffer::new(&buffer))?;

    // Inspect the answers within the response
    let (ipv4_addresses, 
         ipv6_addresses, 
         cnonical_names) = inspect(&res.answers);

    // println!("{:?}", ipv4_addresses);
    // println!("{:?}", ipv6_addresses);
    // println!("{:?}", cnonical_names);

    // The server name has replied us with some IPv4/IPv6 records,
    // meaning that we have reached the end of the hierarchy and
    // we found the IP address of the requested domain
    if !ipv4_addresses.is_empty() || !ipv6_addresses.is_empty() {
        return Ok((ipv4_addresses, 
                   ipv6_addresses, 
                   cnonical_names));
    }

    // The server name has replied us with the CNAME (Canonical Name)
    // of the domain we are looking for. For instance, looking for
    // www.polito.it which is actually webp01.polito.it. Take the
    // first one to be resolved
    if let Some(cname) = cnonical_names.get(0) {
        return resolve(&cname.as_cname().unwrap(), address, depth - 1).await;
    }
    
    // If here, we are not at the end of the hierarchy. We have to ask
    // next name server the IP address of the requested domain. Get the
    // list of authorities
    let authorities: Vec<String> = res
        .authorities
        .iter()
        .filter_map(|auth| {
            if Type::from_u16(auth.atype) == Some(Type::NS) {
                if let RData::NS(ns) = &auth.rdata {
                    Some(ns.to_owned())
                } else { None }
            } else { None }
    }).collect();
    //println!();

    // Using the additional record, find the addresses of such authorities
    // servers... They are supposed to be included by the name servers...
    let addresses: Vec<Ipv4Addr> = res
        .additionals
        .iter()
        .filter_map(|add| {
            if Type::from_u16(add.atype) == Some(Type::A) {
                if let RData::A(ip) = &add.rdata {
                    Some(*ip)
                } else { None }
            } else { None }
    }).collect();
    //println!();

    // Take the first authority address and ask the authority server the IP
    // address which is associated with the domain we are looking for
    for address in addresses {
        if let Ok((ipv4_addresses, 
                   ipv6_addresses, 
                   cnonical_names)) = resolve(domain, &address.to_string(), depth - 1).await {

            // The server name has replied us with some IPv4/IPv6 records,
            // meaning that we have reached the end of the hierarchy and
            // we found the IP address of the requested domain
            if !ipv4_addresses.is_empty() || !ipv6_addresses.is_empty() {
                return Ok((ipv4_addresses, 
                           ipv6_addresses, 
                           cnonical_names));
            }

            // The server name has replied us with the CNAME (Canonical Name)
            // of the domain we are looking for. For instance, looking for
            // www.polito.it which is actually webp01.polito.it. Take the
            // first one to be resolved
            if let Some(cname) = cnonical_names.get(0) {
                return resolve(&cname.as_cname().unwrap(), &address.to_string(), depth - 1).await;
            }      
        }
    }

    // If there are not glue records, it means that we only have the name of
    // the servers, but we do not know anything about their IP addresses.
    // As a consequence, we need to know the IP addresses of the authority
    // servers before continue
    for authority in authorities {
        let root = "198.41.0.4";
        if let Ok((ipv4_addresses, 
                   ipv6_addresses, 
                   cnonical_names)) = resolve(&authority, root, depth - 1).await {
                    
            for ipv4 in ipv4_addresses {
                if let RData::A(ipv4) = ipv4 {
                    if let Ok((ipv4_addresses, 
                               ipv6_addresses, 
                               cnonical_names)) = resolve(domain, &ipv4.to_string(), depth - 1).await {

                        return Ok((ipv4_addresses, 
                                   ipv6_addresses, 
                                   cnonical_names));
                    }
                }
            }
        }
    }

    Err(DnsError::IOError("no valid answer found".into()))
}
