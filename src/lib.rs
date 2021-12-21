pub mod client;
pub mod errors;
pub mod messages;
pub mod network;
mod serialize;
pub mod server;

#[cfg(test)]
mod test {
    use crate::client::{LoginInfo, SOCKSv5Client, UsernamePassword};
    use crate::network::generic::Networklike;
    use crate::network::listener::Listenerlike;
    use crate::network::testing::TestingStack;
    use crate::server::{SOCKSv5Server, SecurityParameters};
    use async_std::channel::bounded;
    use async_std::io::prelude::WriteExt;
    use async_std::task;
    use futures::AsyncReadExt;

    #[test]
    fn unrestricted_login() {
        task::block_on(async {
            let network_stack = TestingStack::default();

            // generate the server
            let security_parameters = SecurityParameters::unrestricted();
            let server = SOCKSv5Server::new(network_stack.clone(), security_parameters);
            server.start("localhost", 9999).await.unwrap();

            let login_info = LoginInfo {
                username_password: None,
            };
            let client = SOCKSv5Client::new(network_stack, login_info, "localhost", 9999).await;

            assert!(client.is_ok());
        })
    }

    #[test]
    fn disallow_unrestricted() {
        task::block_on(async {
            let network_stack = TestingStack::default();

            // generate the server
            let mut security_parameters = SecurityParameters::unrestricted();
            security_parameters.allow_unauthenticated = false;
            let server = SOCKSv5Server::new(network_stack.clone(), security_parameters);
            server.start("localhost", 9998).await.unwrap();

            let login_info = LoginInfo {
                username_password: None,
            };
            let client = SOCKSv5Client::new(network_stack, login_info, "localhost", 9998).await;

            assert!(client.is_err());
        })
    }

    #[test]
    fn password_checks() {
        task::block_on(async {
            let network_stack = TestingStack::default();

            // generate the server
            let security_parameters = SecurityParameters {
                allow_unauthenticated: false,
                allow_connection: None,
                connect_tls: None,
                check_password: Some(|username, password| {
                    username == "awick" && password == "password"
                }),
            };
            let server = SOCKSv5Server::new(network_stack.clone(), security_parameters);
            server.start("localhost", 9997).await.unwrap();

            // try the positive side
            let login_info = LoginInfo {
                username_password: Some(UsernamePassword {
                    username: "awick".to_string(),
                    password: "password".to_string(),
                }),
            };
            let client =
                SOCKSv5Client::new(network_stack.clone(), login_info, "localhost", 9997).await;
            assert!(client.is_ok());

            // try the negative side
            let login_info = LoginInfo {
                username_password: Some(UsernamePassword {
                    username: "adamw".to_string(),
                    password: "password".to_string(),
                }),
            };
            let client = SOCKSv5Client::new(network_stack, login_info, "localhost", 9997).await;
            assert!(client.is_err());
        })
    }

    #[test]
    fn firewall_blocks() {
        task::block_on(async {
            let network_stack = TestingStack::default();

            // generate the server
            let mut security_parameters = SecurityParameters::unrestricted();
            security_parameters.allow_connection = Some(|_, _| false);
            let server = SOCKSv5Server::new(network_stack.clone(), security_parameters);
            server.start("localhost", 9996).await.unwrap();

            let login_info = LoginInfo {
                username_password: None,
            };
            let client = SOCKSv5Client::new(network_stack, login_info, "localhost", 9996).await;

            assert!(client.is_err());
        })
    }

    #[test]
    fn establish_stream() {
        task::block_on(async {
            let mut network_stack = TestingStack::default();

            let target_port = network_stack.listen("localhost", 1337).await.unwrap();

            // generate the server
            let security_parameters = SecurityParameters::unrestricted();
            let server = SOCKSv5Server::new(network_stack.clone(), security_parameters);
            server.start("localhost", 9995).await.unwrap();

            let login_info = LoginInfo {
                username_password: None,
            };

            let mut client = SOCKSv5Client::new(network_stack, login_info, "localhost", 9995)
                .await
                .unwrap();

            task::spawn(async move {
                let mut conn = client.connect("localhost", 1337).await.unwrap();
                conn.write_all(&[1, 3, 3, 7, 9]).await.unwrap();
            });

            let (mut target_connection, _, _) = target_port.accept().await.unwrap();
            let mut read_buffer = [0; 4];
            target_connection
                .read_exact(&mut read_buffer)
                .await
                .unwrap();
            assert_eq!(read_buffer, [1, 3, 3, 7]);
        })
    }

    #[test]
    fn bind_test() {
        task::block_on(async {
            let mut network_stack = TestingStack::default();

            let security_parameters = SecurityParameters::unrestricted();
            let server = SOCKSv5Server::new(network_stack.clone(), security_parameters);
            server.start("localhost", 9994).await.unwrap();

            let login_info = LoginInfo::default();
            let client = SOCKSv5Client::new(network_stack.clone(), login_info, "localhost", 9994)
                .await
                .unwrap();

            let (target_sender, target_receiver) = bounded(1);

            task::spawn(async move {
                let (_, _, mut conn) = client
                    .remote_listen("localhost", 9993, |addr, port| async move {
                        target_sender.send((addr, port)).await.unwrap();
                        Ok(())
                    })
                    .await
                    .unwrap();

                conn.write_all(&[2, 3, 5, 7]).await.unwrap();
            });

            let (target_addr, target_port) = target_receiver.recv().await.unwrap();
            let mut stream = network_stack
                .connect(target_addr, target_port)
                .await
                .unwrap();
            let mut read_buffer = [0; 4];
            stream.read_exact(&mut read_buffer).await.unwrap();
            assert_eq!(read_buffer, [2, 3, 5, 7]);
        })
    }
}
