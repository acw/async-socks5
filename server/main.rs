mod config;

use async_socks5::server::{SOCKSv5Server, SecurityParameters};
use config::Config;
use tracing::Instrument;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let config = Config::derive()?;

    let fmt_layer = fmt::layer().with_target(false);
    let filter_layer = EnvFilter::builder()
        .with_default_directive(config.log_level.into())
        .from_env()?;

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();

    tracing::trace!("Parsed configuration: {:?}", config);

    let core_server = SOCKSv5Server::new(SecurityParameters {
        allow_unauthenticated: true,
        allow_connection: None,
        check_password: None,
        connect_tls: None,
    });

    let mut running_servers = vec![];

    for server_def in config.server_definitions {
        let span = tracing::trace_span!(
            "",
            server_name = %server_def.name,
            interface = ?server_def.interface,
            address = %server_def.address,
        );

        let result = core_server
            .start(server_def.address.ip(), server_def.address.port())
            .instrument(span)
            .await;

        match result {
            Ok(x) => running_servers.push(x),
            Err(e) => tracing::error!(
                server = %server_def.name,
                interface = ?server_def.interface,
                address = %server_def.address,
                "Failure in launching server: {}",
                e
            ),
        }
    }

    while !running_servers.is_empty() {
        let (initial_result, _idx, next_runners) =
            futures::future::select_all(running_servers).await;

        match initial_result {
            Ok(Ok(())) => tracing::info!("server completed successfully"),
            Ok(Err(e)) => tracing::error!("error in running server: {}", e),
            Err(e) => tracing::error!("error joining server: {}", e),
        }

        running_servers = next_runners;
    }

    Ok(())
}
