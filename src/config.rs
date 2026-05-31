use std::path::Path;

const LISTEN_PORT: u16 = 31000;
const BUILTIN_BOOTSTRAP_RECORDS: &[&str] = &[];
const BUILTIN_TRUST_UPDATES: &[&str] = &[];
const PUBLIC_IP: Option<&str> = None;

const WALLET_ACCESS_RELAY_RECORD: Option<&str> = None;
const WALLET_SUBMISSION_GATEWAY_RECORD: Option<&str> = None;
const ACCESS_RELAY_GATEWAY_RECORDS: &[&str] = &[];
const SUBMISSION_GATEWAY_ALLOWED_RELAYS: &[&str] = &[];
const SUBMISSION_GATEWAY_VALIDATOR_CONTROL_BASE_PATH: Option<&str> = None;
const WALLET_PROOF_ASSISTANT_RECORD: Option<&str> = None;
const WALLET_DISCOVERY_RECORD: Option<&str> = None;
const WALLET_DISCOVERY_MIRROR_RECORDS: &[&str] = &[];
const DISCOVERY_STATE_PATH: Option<&str> = None;
const DISCOVERY_QUERY_ONLY_REPLICA: bool = false;

#[derive(Debug, Clone)]
pub struct Config {
    pub net: Net,
    pub storage: Storage,
    pub ingress: Ingress,
    pub proof_assistant: ProofAssistant,
    pub discovery: Discovery,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            net: Net::default(),
            storage: Storage::default(),
            ingress: Ingress::default(),
            proof_assistant: ProofAssistant::default(),
            discovery: Discovery::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Net {
    pub listen_port: u16,
    pub bootstrap: Vec<String>,
    pub trust_updates: Vec<String>,
    pub public_ip: Option<String>,
}

impl Default for Net {
    fn default() -> Self {
        Self {
            listen_port: LISTEN_PORT,
            bootstrap: strings(BUILTIN_BOOTSTRAP_RECORDS),
            trust_updates: strings(BUILTIN_TRUST_UPDATES),
            public_ip: PUBLIC_IP.map(str::to_string),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Storage {
    pub path: String,
}

impl Default for Storage {
    fn default() -> Self {
        Self {
            path: resolve_storage_path("unchained_data"),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Ingress {
    pub wallet: WalletIngress,
    pub access_relay: AccessRelay,
    pub submission_gateway: SubmissionGateway,
}

#[derive(Debug, Clone, Default)]
pub struct ProofAssistant {
    pub wallet: WalletProofAssistant,
}

#[derive(Debug, Clone, Default)]
pub struct Discovery {
    pub wallet: WalletDiscovery,
    pub server: DiscoveryServer,
}

#[derive(Debug, Clone)]
pub struct WalletIngress {
    pub relay: Option<String>,
    pub gateway: Option<String>,
}

impl Default for WalletIngress {
    fn default() -> Self {
        Self {
            relay: WALLET_ACCESS_RELAY_RECORD.map(str::to_string),
            gateway: WALLET_SUBMISSION_GATEWAY_RECORD.map(str::to_string),
        }
    }
}

#[derive(Debug, Clone)]
pub struct WalletProofAssistant {
    pub server: Option<String>,
}

impl Default for WalletProofAssistant {
    fn default() -> Self {
        Self {
            server: WALLET_PROOF_ASSISTANT_RECORD.map(str::to_string),
        }
    }
}

#[derive(Debug, Clone)]
pub struct WalletDiscovery {
    pub server: Option<String>,
    pub mirrors: Vec<String>,
}

impl Default for WalletDiscovery {
    fn default() -> Self {
        Self {
            server: WALLET_DISCOVERY_RECORD.map(str::to_string),
            mirrors: strings(WALLET_DISCOVERY_MIRROR_RECORDS),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AccessRelay {
    pub gateways: Vec<String>,
}

impl Default for AccessRelay {
    fn default() -> Self {
        Self {
            gateways: strings(ACCESS_RELAY_GATEWAY_RECORDS),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SubmissionGateway {
    pub allowed_relays: Vec<String>,
    pub validator_control_base_path: Option<String>,
}

impl Default for SubmissionGateway {
    fn default() -> Self {
        Self {
            allowed_relays: strings(SUBMISSION_GATEWAY_ALLOWED_RELAYS),
            validator_control_base_path: SUBMISSION_GATEWAY_VALIDATOR_CONTROL_BASE_PATH
                .map(str::to_string),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DiscoveryServer {
    pub state_path: Option<String>,
    pub query_only_replica: bool,
}

impl Default for DiscoveryServer {
    fn default() -> Self {
        Self {
            state_path: DISCOVERY_STATE_PATH.map(str::to_string),
            query_only_replica: DISCOVERY_QUERY_ONLY_REPLICA,
        }
    }
}

pub fn load() -> Config {
    Config::default()
}

pub fn resolve_storage_path(path: &str) -> String {
    if Path::new(path).is_relative() {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());
        Path::new(&home)
            .join(".unchained")
            .join(path)
            .to_string_lossy()
            .into_owned()
    } else {
        path.to_string()
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}
