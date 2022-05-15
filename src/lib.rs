pub mod client;
pub mod server;

mod address;
mod messages;
mod security_parameters;

#[cfg(test)]
mod test {
    use crate::address::SOCKSv5Address;
    use crate::client::{LoginInfo, SOCKSv5Client, UsernamePassword};
    use crate::security_parameters::SecurityParameters;
    use crate::server::SOCKSv5Server;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpSocket, TcpStream};
    use tokio::sync::oneshot;
    use tokio::task;

    #[tokio::test]
    async fn unrestricted_login() {
        // generate the server
        let security_parameters = SecurityParameters::unrestricted();
        let server = SOCKSv5Server::new(security_parameters);
        server.start("localhost", 9999).await.unwrap();

        let login_info = LoginInfo {
            username_password: None,
        };
        let client = SOCKSv5Client::new(login_info, "localhost", 9999).await;

        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn disallow_unrestricted() {
        // generate the server
        let mut security_parameters = SecurityParameters::unrestricted();
        security_parameters.allow_unauthenticated = false;
        let server = SOCKSv5Server::new(security_parameters);
        server.start("localhost", 9998).await.unwrap();

        let login_info = LoginInfo::default();
        let client = SOCKSv5Client::new(login_info, "localhost", 9998).await;

        assert!(client.is_err());
    }

    #[tokio::test]
    async fn password_checks() {
        // generate the server
        let security_parameters = SecurityParameters {
            allow_unauthenticated: false,
            allow_connection: None,
            connect_tls: None,
            check_password: Some(|username, password| {
                username == "awick" && password == "password"
            }),
        };
        let server = SOCKSv5Server::new(security_parameters);
        server.start("localhost", 9997).await.unwrap();

        // try the positive side
        let login_info = LoginInfo {
            username_password: Some(UsernamePassword {
                username: "awick".to_string(),
                password: "password".to_string(),
            }),
        };
        let client = SOCKSv5Client::new(login_info, "localhost", 9997).await;
        assert!(client.is_ok());

        // try the negative side
        let login_info = LoginInfo {
            username_password: Some(UsernamePassword {
                username: "adamw".to_string(),
                password: "password".to_string(),
            }),
        };
        let client = SOCKSv5Client::new(login_info, "localhost", 9997).await;
        assert!(client.is_err());
    }

    #[tokio::test]
    async fn firewall_blocks() {
        // generate the server
        let mut security_parameters = SecurityParameters::unrestricted();
        security_parameters.allow_connection = Some(|_| false);
        let server = SOCKSv5Server::new(security_parameters);
        server.start("localhost", 9996).await.unwrap();

        let login_info = LoginInfo::new();
        let client = SOCKSv5Client::new(login_info, "localhost", 9996).await;

        assert!(client.is_err());
    }

    #[tokio::test]
    async fn establish_stream() -> io::Result<()> {
        let target_socket = TcpSocket::new_v4()?;
        target_socket.bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            1337,
        ))?;
        let target_port = target_socket.listen(1)?;

        // generate the server
        let security_parameters = SecurityParameters::unrestricted();
        let server = SOCKSv5Server::new(security_parameters);
        server.start("localhost", 9995).await.unwrap();

        let login_info = LoginInfo {
            username_password: None,
        };

        let mut client = SOCKSv5Client::new(login_info, "localhost", 9995)
            .await
            .unwrap();

        task::spawn(async move {
            let mut conn = client.connect("localhost", 1337).await.unwrap();
            conn.write_all(&[1, 3, 3, 7, 9]).await.unwrap();
        });

        let (mut target_connection, _) = target_port.accept().await.unwrap();
        let mut read_buffer = [0; 4];
        target_connection
            .read_exact(&mut read_buffer)
            .await
            .unwrap();
        assert_eq!(read_buffer, [1, 3, 3, 7]);
        Ok(())
    }

    #[tokio::test]
    async fn bind_test() -> io::Result<()> {
        let security_parameters = SecurityParameters::unrestricted();
        let server = SOCKSv5Server::new(security_parameters);
        server.start("localhost", 9994).await.unwrap();

        let login_info = LoginInfo::default();
        let client = SOCKSv5Client::new(login_info, "localhost", 9994)
            .await
            .unwrap();

        let (target_sender, target_receiver) = oneshot::channel();

        task::spawn(async move {
            let (_, _, mut conn) = client
                .remote_listen("localhost", 9993, |addr, port| async move {
                    target_sender.send((addr, port)).unwrap();
                    Ok(())
                })
                .await
                .unwrap();

            conn.write_all(&[2, 3, 5, 7]).await.unwrap();
        });

        let (target_addr, target_port) = target_receiver.await.unwrap();
        let mut stream = match target_addr {
            SOCKSv5Address::IP4(x) => TcpStream::connect((x, target_port)).await?,
            SOCKSv5Address::IP6(x) => TcpStream::connect((x, target_port)).await?,
            SOCKSv5Address::Hostname(x) => TcpStream::connect((x, target_port)).await?,
        };
        let mut read_buffer = [0; 4];
        stream.read_exact(&mut read_buffer).await.unwrap();
        assert_eq!(read_buffer, [2, 3, 5, 7]);
        Ok(())
    }
}
