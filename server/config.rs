mod cmdline;
mod config_file;

use self::cmdline::Arguments;
use self::config_file::ConfigFile;
use clap::Parser;
use if_addrs::IfAddr;
use std::io;
use std::net::{AddrParseError, IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::str::FromStr;
use thiserror::Error;
use tracing::metadata::LevelFilter;
use xdg::BaseDirectoriesError;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error(transparent)]
    CommandLineError(#[from] clap::Error),
    #[error("Error querying XDG base directories: {0}")]
    XdgError(#[from] BaseDirectoriesError),
    #[error(transparent)]
    IOError(#[from] io::Error),
    #[error("TOML processing error: {0}")]
    TomlError(#[from] toml::de::Error),
    #[error("Server '{0}' specifies an interface ({1}) with no addresses")]
    NoAddressForInterface(String, String),
    #[error("Server '{0}' specifies an address we couldn't parse: {1}")]
    AddressParseError(String, AddrParseError),
}

#[derive(Debug)]
pub struct Config {
    pub log_level: LevelFilter,
    pub server_definitions: Vec<ServerDefinition>,
}

#[derive(Debug)]
pub struct ServerDefinition {
    pub name: String,
    pub start: bool,
    pub interface: Option<String>,
    pub address: SocketAddr,
    pub log_level: LevelFilter,
}

impl Config {
    /// Generate a configuration by reading the command line arguments and any
    /// defined config file, generating the actual arguments that we'll use for
    /// operating the daemon.
    pub fn derive() -> Result<Self, ConfigError> {
        let command_line = Arguments::try_parse()?;
        let mut config_file = ConfigFile::read(command_line.config_file)?;
        let nic_addresses = if_addrs::get_if_addrs()?;

        let log_level = command_line
            .log_level
            .or(config_file.log_level)
            .unwrap_or(LevelFilter::ERROR);

        let mut server_definitions = Vec::new();
        let servers_to_start: Vec<String> = config_file
            .start_servers
            .map(|x| x.split(',').map(|v| v.to_string()).collect())
            .unwrap_or_default();

        for (name, config_info) in config_file.servers.drain() {
            let start = servers_to_start.contains(&name);
            let log_level = config_info.log_level.unwrap_or(log_level);
            let port = config_info.port.unwrap_or(1080);
            let mut interface = None;
            let mut address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port));

            match (config_info.interface, config_info.address) {
                // if the user provides us nothing, we'll just use a blank address and
                // no interface association
                (None, None) => {}

                // if the user provides us an interface but no address, we'll see if we can
                // find the interface and pull a reasonable address from it.
                (Some(given_interface), None) => {
                    let mut found_it = false;

                    for card_interface in nic_addresses.iter() {
                        if card_interface.name == given_interface {
                            interface = Some(given_interface.clone());
                            address = SocketAddr::new(addr_convert(&card_interface.addr), port);
                            found_it = true;
                            break;
                        }
                    }

                    if !found_it {
                        return Err(ConfigError::NoAddressForInterface(name, given_interface));
                    }
                }

                // if the user provides us an address but no interface, we'll quickly see if
                // we can find that address in our interface list ... but we won't insist on
                // it.
                (None, Some(address_string)) => {
                    let read_address = IpAddr::from_str(&address_string)
                        .map_err(|x| ConfigError::AddressParseError(name.clone(), x))?;

                    interface = None;
                    address = SocketAddr::new(read_address, port);
                    for card_interface in nic_addresses.iter() {
                        if addrs_match(&card_interface.addr, &read_address) {
                            interface = Some(card_interface.name.clone());
                            break;
                        }
                    }
                }

                // if the user provides both, we'll check to make sure that they match.
                (Some(given_interface), Some(address_string)) => {
                    let read_address = IpAddr::from_str(&address_string)
                        .map_err(|x| ConfigError::AddressParseError(name.clone(), x))?;
                    let mut inferred_interface = None;
                    let mut good_to_go = false;

                    address = SocketAddr::new(read_address, port);
                    for card_interface in nic_addresses.iter() {
                        if addrs_match(&card_interface.addr, &read_address) {
                            if card_interface.name == given_interface {
                                interface = Some(given_interface.clone());
                                good_to_go = true;
                                break;
                            } else {
                                inferred_interface = Some(card_interface.name.clone());
                            }
                        }
                    }

                    if !good_to_go {
                        if let Some(inferred_interface) = inferred_interface {
                            tracing::warn!("Address {} is associated with interface {}, not {}; using it instead", read_address, inferred_interface, given_interface);
                        } else {
                            tracing::warn!(
                                "Address {} is not associated with interface {}, or any interface.",
                                read_address,
                                given_interface
                            );
                        }
                    }
                }
            }

            server_definitions.push(ServerDefinition {
                name,
                start,
                interface,
                address,
                log_level,
            });
        }

        Ok(Config {
            log_level,
            server_definitions,
        })
    }
}

fn addr_convert(x: &if_addrs::IfAddr) -> IpAddr {
    match x {
        if_addrs::IfAddr::V4(x) => IpAddr::V4(x.ip),
        if_addrs::IfAddr::V6(x) => IpAddr::V6(x.ip),
    }
}

fn addrs_match(x: &if_addrs::IfAddr, y: &IpAddr) -> bool {
    match (x, y) {
        (IfAddr::V4(x), IpAddr::V4(y)) => &x.ip == y,
        (IfAddr::V6(x), IpAddr::V6(y)) => &x.ip == y,
        _ => false,
    }
}
