// src/auth/mod.rs
pub mod error;
pub mod anisette;
pub mod crypto;
pub mod gsa;
pub mod srp;
pub mod twofa;
pub mod bridge;

use anyhow::Result;
use std::collections::HashMap;

pub use anisette::AnisetteClient;
pub use gsa::GsaClient;
pub use srp::SrpFlow;
pub use twofa::TwoFAHandler;
pub use bridge::{run_python_login, run_python_test_session, is_python_available};

pub struct Fortiva {
    pub gsa: GsaClient,
    pub srp: SrpFlow,
    pub twofa: TwoFAHandler,
    pub user_id: String,
    pub device_id: String,
    pub client_info: String,
}

impl Fortiva {
    pub fn new(anisette_url: Option<&str>) -> Result<Self> {
        let user_id = uuid::Uuid::new_v4().to_string().to_uppercase();
        let device_id = uuid::Uuid::new_v4().to_string().to_uppercase();

        let anisette = AnisetteClient::new(anisette_url);
        let gsa = GsaClient::new(anisette, user_id.clone(), device_id.clone());

        Ok(Self {
            gsa,
            srp: SrpFlow::new(),
            twofa: TwoFAHandler::new(),
            user_id,
            device_id,
            client_info: crate::constants::DEFAULT_CLIENT_INFO.to_string(),
        })
    }

    pub fn generate_anisette_headers(&mut self) -> Result<HashMap<String, String>> {
        self.gsa.anisette.fetch(true)
    }

    pub fn generate_meta_headers(&self) -> HashMap<String, String> {
        AnisetteClient::get_meta_headers(&self.user_id, &self.device_id)
    }

    pub fn authenticate(&mut self, apple_id: &str, password: &str) -> Result<AuthResult> {
        self.srp
            .authenticate(&mut self.gsa, &mut self.twofa, apple_id, password, 0)
    }
}

#[derive(Debug, Clone)]
pub struct AuthResult {
    pub user_id: String,
    pub authenticated: bool,
    pub dsid: Option<String>,
    pub session_token: Option<String>,
    pub needs_2fa: bool,
}
