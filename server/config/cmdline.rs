use clap::Parser;
use std::path::PathBuf;
use tracing::metadata::LevelFilter;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Arguments {
    #[clap(
        short,
        long,
        help = "Use the given config file, rather than $XDG_CONFIG_DIR/socks5.toml"
    )]
    pub config_file: Option<PathBuf>,

    #[clap(
        short,
        long,
        help = "Default logging to the given level. (Defaults to ERROR if not given)"
    )]
    pub log_level: Option<LevelFilter>,

    #[clap(
        short,
        long,
        help = "Start only the named server(s) from the config file. For more than one, use comma-separated values or multiple instances of --start"
    )]
    pub start: Vec<String>,

    #[clap(
        short,
        long = "validate",
        help = "Do not actually start any servers; just validate the config file."
    )]
    pub validate_only: bool,
}
