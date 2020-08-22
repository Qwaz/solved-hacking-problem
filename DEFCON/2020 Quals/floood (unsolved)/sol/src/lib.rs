pub mod protocol;

use self::protocol::*;
use pretty_hex::*;
use socket2::Socket;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

pub struct ControlSocket {
    inner: Socket,
    pub debug: bool,
}

impl ControlSocket {
    pub fn new<A: ToSocketAddrs>(addr: A) -> Self {
        // https://rust-lang-nursery.github.io/rust-cookbook/net/server.html
        let socket_addr = SocketAddr::from(([0, 0, 0, 0], 0));

        let udp_socket = UdpSocket::bind(socket_addr).expect("failed to bind");
        udp_socket.connect(addr).expect("failed to connect");
        udp_socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("failed to set timeout");

        ControlSocket {
            inner: udp_socket.into(),
            debug: true,
        }
    }

    pub fn query(&mut self, req: Request) -> Vec<Response> {
        if self.debug {
            let bytes: Vec<u8> = bincode::serialize(&req).unwrap();
            println!("Send: {}", bytes.hex_dump())
        }
        bincode::serialize_into(&mut self.inner, &req).expect("failed to serialize");

        let mut responses = Vec::new();
        let mut buf = [0; 2048];
        loop {
            match self.inner.recv(&mut buf) {
                Ok(bytes) => {
                    if self.debug {
                        println!("Recv: {}", (&buf[..bytes]).hex_dump());
                    }
                    responses
                        .push(bincode::deserialize(&buf[..bytes]).expect("failed to deserialize"));
                }
                _ => break,
            }
        }

        responses
    }
}

pub struct LogMonitorSocket {
    inner: Socket,
}

impl LogMonitorSocket {
    pub fn new(port: u16) -> Self {
        let socket_addr = SocketAddr::from(([0, 0, 0, 0], port));

        let udp_socket = UdpSocket::bind(socket_addr).expect("failed to bind");

        LogMonitorSocket {
            inner: udp_socket.into(),
        }
    }

    pub fn monitor(&mut self) -> ! {
        let mut buf = [0; 2048];
        loop {
            if let Ok(bytes) = self.inner.recv(&mut buf) {
                println!("Recv: {}", (&buf[..bytes]).hex_dump());
                match bincode::deserialize::<Detection>(&buf[..bytes]) {
                    Ok(detection) => {
                        dbg!(detection);
                    }
                    Err(e) => println!("Error: {:?}", e),
                }
            }
        }
    }
}
