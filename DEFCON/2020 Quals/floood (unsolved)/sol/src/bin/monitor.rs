use floood::LogMonitorSocket;

fn main() {
    println!("[!] Monitoring..");

    let mut socket = LogMonitorSocket::new(12345);
    socket.monitor();
}
