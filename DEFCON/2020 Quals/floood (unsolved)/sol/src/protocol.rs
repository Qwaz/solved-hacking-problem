use serde::{Deserialize, Serialize};

// Control Protocol
#[derive(Debug, Deserialize, Serialize)]
pub enum Request {
    GetRules,
    AddRule { rule: Rule },
    DeleteRule { label: String },
    GetTapEndpoint,
    GetLogEndpoint,
    SetLogEndpoint { address: String, port: u16 },
}

#[derive(Debug, Deserialize, Serialize)]
pub enum Response {
    GetRules { rules: Vec<Rule> },
    AddRule,
    DeleteRule,
    GetTapEndpoint { address: String, port: u16 },
    GetLogEndpoint { address: String, port: u16 },
    SetLogEndpoint,
    Error(String),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Rule {
    pub label: String,
    protocol: IpProtocol,
    source_address: ipnetwork::IpNetwork,
    target_address: ipnetwork::IpNetwork,
    source_port: Option<u16>,
    target_port: Option<u16>,
    content: String,
}

impl Rule {
    pub fn new(
        label: impl ToString,
        protocol: IpProtocol,
        source: &str,
        target: &str,
        source_port: Option<u16>,
        target_port: Option<u16>,
        content: impl ToString,
    ) -> Self {
        Rule {
            label: label.to_string(),
            protocol,
            source_address: source.parse().unwrap(),
            target_address: target.parse().unwrap(),
            source_port,
            target_port,
            content: content.to_string(),
        }
    }
}

#[derive(Debug)]
pub struct CompiledRule {
    pub rule: Rule,
    content_regex: regex::bytes::Regex,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum IpProtocol {
    Tcp,
    Udp,
}

// Log Protocol
#[derive(Debug, Deserialize, Serialize)]
pub struct Detection {
    pub rule: String,
    pub source_address: u32,
    pub target_address: u32,
    pub source_port: u16,
    pub target_port: u16,
    pub content: Vec<u8>,
}
