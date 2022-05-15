use std::net::SocketAddr;

/// The security parameters that you can assign to the server, to make decisions
/// about the weirdos it accepts as users. It is recommended that you only use
/// wide open connections when you're 100% sure that the server will only be
/// accessible locally.
#[derive(Clone)]
pub struct SecurityParameters {
    /// Allow completely unauthenticated connections. You should be very, very
    /// careful about setting this to true, especially if you don't provide a
    /// guard to ensure that you're getting connections from reasonable places.
    pub allow_unauthenticated: bool,
    /// An optional function that can serve as a firewall for new connections.
    /// Return true if the connection should be allowed to continue, false if
    /// it shouldn't. This check happens before any data is read from or written
    /// to the connecting party.
    pub allow_connection: Option<fn(&SocketAddr) -> bool>,
    /// An optional function to check a user name (first argument) and password
    /// (second argument). Return true if the username / password is good, false
    /// if not.
    pub check_password: Option<fn(&str, &str) -> bool>,
    /// An optional function to transition the stream from an unencrypted one to
    /// an encrypted on. The assumption is you're using something like `rustls`
    /// to make this happen; the exact mechanism is outside the scope of this
    /// particular crate. If the connection shouldn't be allowed for some reason
    /// (a bad certificate or handshake, for example), then return None; otherwise,
    /// return the new stream.
    pub connect_tls: Option<fn() -> Option<()>>,
}

impl SecurityParameters {
    /// Generates a `SecurityParameters` object that's empty. It won't accept
    /// anything, because it has no mechanisms it can use to actually authenticate
    /// a user and yet won't allow unauthenticated connections.
    pub fn new() -> SecurityParameters {
        SecurityParameters {
            allow_unauthenticated: false,
            allow_connection: None,
            check_password: None,
            connect_tls: None,
        }
    }

    /// Generates a `SecurityParameters` object that does not, in any way,
    /// restrict who can log in. It also will not induce any transition into
    /// TLS. Use this at your own risk ... or, really, just don't use this,
    /// ever, and certainly not in production.
    pub fn unrestricted() -> SecurityParameters {
        SecurityParameters {
            allow_unauthenticated: true,
            allow_connection: None,
            check_password: None,
            connect_tls: None,
        }
    }

    /// Use the provided function to check incoming connections before proceeding
    /// with the rest of the handshake.
    pub fn check_connections(mut self, checker: fn(&SocketAddr) -> bool) -> SecurityParameters {
        self.allow_connection = Some(checker);
        self
    }

    /// Use the provided function to check usernames and passwords provided
    /// to the server.
    pub fn password_check(mut self, checker: fn(&str, &str) -> bool) -> SecurityParameters {
        self.check_password = Some(checker);
        self
    }

    /// Use the provide function to validate a TLS connection, and transition it
    /// to the new stream type. If the handshake fails, return `None` instead of
    /// `Some`. (And maybe log it somewhere, you know.)
    pub fn tls_converter(mut self, converter: fn() -> Option<()>) -> SecurityParameters {
        self.connect_tls = Some(converter);
        self
    }
}

impl Default for SecurityParameters {
    fn default() -> Self {
        Self::new()
    }
}
