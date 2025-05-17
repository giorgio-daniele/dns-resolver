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
    let sock = UdpSocket::bind("127.0.0.1:53")
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
            let handle = tokio::spawn(async move {
                proc(dns, addr).await
            });

            match handle.await {
                Ok(Ok(resp)) => {
                    //println!("{:#?}", Dns::decode( &mut Buffer::new(resp.to_vec())));
                    // Send the response to the client using the original socket
                    sock.send_to(&resp, addr)
                        .await
                        .map_err(|_| 
                            DnsError::IOError(
                                String::from("can't write dns packet to client")))?;
                }
                Ok(Err(e)) => {
                    println!("{:?}", e);
                }
                Err(e) => {
                    println!("{:?}", e);
                }
            }
        }
    }
}
