use async_socks5::network::Builtin;
use async_socks5::server::{SOCKSv5Server, SecurityParameters};
use async_std::io;
use futures::stream::StreamExt;
use simplelog::{ColorChoice, CombinedLogger, Config, LevelFilter, TermLogger, TerminalMode};

#[async_std::main]
async fn main() -> Result<(), io::Error> {
    CombinedLogger::init(vec![TermLogger::new(
        LevelFilter::Debug,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )])
    .expect("Couldn't initialize logger");

    let params = SecurityParameters {
        allow_unauthenticated: true,
        allow_connection: None,
        check_password: None,
        connect_tls: None,
    };

    let mut server = SOCKSv5Server::new(Builtin::new(), params);
    server.start("127.0.0.1", 9999).await?;

    let mut responses = Box::pin(server.subserver_results());

    while let Some(response) = responses.next().await {
        if let Err(e) = response {
            println!("Server failed with: {}", e);
        }
    }

    Ok(())
}
