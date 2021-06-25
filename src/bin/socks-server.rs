use async_socks5::network::Builtin;
use async_socks5::server::{SOCKSv5Server, SecurityParameters};
use async_std::io;
use async_std::net::TcpListener;
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

    let main_listener = TcpListener::bind("127.0.0.1:0").await?;
    let params = SecurityParameters {
        allow_unauthenticated: false,
        allow_connection: None,
        check_password: None,
        connect_tls: None,
    };

    let server = SOCKSv5Server::new(Builtin::new(), params, main_listener);

    server.run().await?;

    Ok(())
}
