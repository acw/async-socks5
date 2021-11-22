use crate::messages::ServerResponseStatus;
use crate::network::address::SOCKSv5Address;
use crate::network::datagram::GenericDatagramSocket;
use crate::network::listener::GenericListener;
use crate::network::stream::GenericStream;
use async_trait::async_trait;
use std::fmt::{Debug, Display};

#[async_trait]
pub trait Networklike {
    /// The error type for things that fail on this network. Apologies in advance
    /// for using only one; if you have a use case for separating your errors,
    /// please shoot the author(s) and email to split this into multiple types, one
    /// for each trait function.
    type Error: Debug + Display + IntoErrorResponse + Send;

    /// Connect to the given address and port, over this kind of network. The
    /// underlying stream should behave somewhat like a TCP stream ... which
    /// may be exactly what you're using. However, in order to support tunnelling
    /// scenarios (i.e., using another proxy, going through Tor or SSH, etc.) we
    /// work generically over any stream-like object.
    async fn connect<A: Send + Into<SOCKSv5Address>>(
        &mut self,
        addr: A,
        port: u16,
    ) -> Result<GenericStream, Self::Error>;

    /// Listen for connections on the given address and port, returning a generic
    /// listener socket to use in the future.
    async fn listen<A: Send + Into<SOCKSv5Address>>(
        &mut self,
        addr: A,
        port: u16,
    ) -> Result<GenericListener<Self::Error>, Self::Error>;

    /// Bind a socket for the purposes of doing some datagram communication. NOTE!
    /// this is only for UDP-like communication, not for generic connecting or
    /// listening! Maybe obvious from the types, but POSIX has overtrained many
    /// of us.
    ///
    /// Recall when using these functions that datagram protocols allow for packet
    /// loss and out-of-order delivery. So ... be warned.
    async fn bind<A: Send + Into<SOCKSv5Address>>(
        &mut self,
        addr: A,
        port: u16,
    ) -> Result<GenericDatagramSocket<Self::Error>, Self::Error>;
}

/// This trait is a hack; sorry about that. The thing is, we want to be able to
/// convert Errors from the `Networklike` trait into a `ServerResponseStatus`,
/// but want to do so on references to the error object rather than the actual
/// object. This is for the paired reason that (a) we want to be able to use
/// the errors in multiple places -- for example, to return a value to the client
/// and then also to whoever called the function -- and (b) some common errors
/// (I'm looking at you, `io::Error`) aren't `Clone`. So ... hence this overly-
/// specific trait.
pub trait IntoErrorResponse {
    #[allow(clippy::wrong_self_convention)]
    fn into_response(&self) -> ServerResponseStatus;
}
