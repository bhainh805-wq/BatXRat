use playit_agent_core::{
    network::{origin_lookup::OriginLookup, tcp::tcp_settings::TcpSettings, udp::udp_settings::UdpSettings},
    playit_agent::{PlayitAgent, PlayitAgentSettings}
};
use playit_api_client::PlayitApi;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::thread;

struct PlayitSecret {
    secret: RwLock<Option<String>>,
}

impl PlayitSecret {
    fn new(secret: String) -> Self {
        PlayitSecret {
            secret: RwLock::new(Some(secret)),
        }
    }

    async fn create_api(&self) -> Result<PlayitApi, Box<dyn std::error::Error>> {
        let secret = self.secret.read().await.as_ref().unwrap().clone();
        Ok(PlayitApi::create("https://api.playit.gg".to_string(), Some(secret)))
    }
}

async fn run_agent() -> Result<(), Box<dyn std::error::Error>> {
    // Setup logging
    tracing_subscriber::fmt().init();

    let secret = PlayitSecret::new("63f76eb73dff8ffd302371cf5207d4949875f298cb1ca0a3cd03c89f82ddc769".to_string());

    let api = secret.create_api().await?;

    let lookup = Arc::new(OriginLookup::default());
    lookup.update_from_run_data(&api.agents_rundata().await?).await;

    let settings = PlayitAgentSettings {
        udp_settings: UdpSettings::default(),
        tcp_settings: TcpSettings::default(),
        api_url: "https://api.playit.gg".to_string(),
        secret_key: secret.secret.read().await.as_ref().unwrap().clone(),
    };

    let runner = PlayitAgent::new(settings, lookup).await?;

    runner.run().await;

    Ok(())
}

#[no_mangle]
pub extern "C" fn start_agent() {
    thread::spawn(|| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(run_agent()).unwrap();
    });
}
