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
    use async_std::io::prelude::WriteExt;
    use async_std::task;
    use futures::AsyncReadExt;

    #[test]
    fn unrestricted_login() {
        task::block_on(async {
            let mut network_stack = TestingStack::default();

            // generate the server
            let security_parameters = SecurityParameters::unrestricted();
            let default_port = network_stack.listen("localhost", 9999).await.unwrap();
            let server =
                SOCKSv5Server::new(network_stack.clone(), security_parameters, default_port);

            let _server_task = task::spawn(async move { server.run().await });

            let stream = network_stack.connect("localhost", 9999).await.unwrap();
            let login_info = LoginInfo {
                username_password: None,
            };
            let client = SOCKSv5Client::new(network_stack, stream, &login_info).await;

            assert!(client.is_ok());
        })
    }

    #[test]
    fn disallow_unrestricted() {
        task::block_on(async {
            let mut network_stack = TestingStack::default();

            // generate the server
            let mut security_parameters = SecurityParameters::unrestricted();
            security_parameters.allow_unauthenticated = false;
            let default_port = network_stack.listen("localhost", 9999).await.unwrap();
            let server =
                SOCKSv5Server::new(network_stack.clone(), security_parameters, default_port);

            let _server_task = task::spawn(async move { server.run().await });

            let stream = network_stack.connect("localhost", 9999).await.unwrap();
            let login_info = LoginInfo {
                username_password: None,
            };
            let client = SOCKSv5Client::new(network_stack, stream, &login_info).await;

            assert!(client.is_err());
        })
    }

    #[test]
    fn password_checks() {
        task::block_on(async {
            let mut network_stack = TestingStack::default();

            // generate the server
            let security_parameters = SecurityParameters {
                allow_unauthenticated: false,
                allow_connection: None,
                connect_tls: None,
                check_password: Some(|username, password| {
                    username == "awick" && password == "password"
                }),
            };
            let default_port = network_stack.listen("localhost", 9999).await.unwrap();
            let server =
                SOCKSv5Server::new(network_stack.clone(), security_parameters, default_port);

            let _server_task = task::spawn(async move { server.run().await });

            // try the positive side
            let stream = network_stack.connect("localhost", 9999).await.unwrap();
            let login_info = LoginInfo {
                username_password: Some(UsernamePassword {
                    username: "awick".to_string(),
                    password: "password".to_string(),
                }),
            };
            let client = SOCKSv5Client::new(network_stack.clone(), stream, &login_info).await;
            assert!(client.is_ok());

            // try the negative side
            let stream = network_stack.connect("localhost", 9999).await.unwrap();
            let login_info = LoginInfo {
                username_password: Some(UsernamePassword {
                    username: "adamw".to_string(),
                    password: "password".to_string(),
                }),
            };
            let client = SOCKSv5Client::new(network_stack, stream, &login_info).await;
            assert!(client.is_err());
        })
    }

    #[test]
    fn firewall_blocks() {
        task::block_on(async {
            let mut network_stack = TestingStack::default();

            // generate the server
            let mut security_parameters = SecurityParameters::unrestricted();
            security_parameters.allow_connection = Some(|_, _| false);
            let default_port = network_stack.listen("localhost", 9999).await.unwrap();
            let server =
                SOCKSv5Server::new(network_stack.clone(), security_parameters, default_port);

            let _server_task = task::spawn(async move { server.run().await });

            let stream = network_stack.connect("localhost", 9999).await.unwrap();
            let login_info = LoginInfo {
                username_password: None,
            };
            let client = SOCKSv5Client::new(network_stack, stream, &login_info).await;

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
            let default_port = network_stack.listen("localhost", 9999).await.unwrap();
            let server =
                SOCKSv5Server::new(network_stack.clone(), security_parameters, default_port);

            let _server_task = task::spawn(async move { server.run().await });

            let stream = network_stack.connect("localhost", 9999).await.unwrap();
            let login_info = LoginInfo {
                username_password: None,
            };

            let mut client = SOCKSv5Client::new(network_stack, stream, &login_info)
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
}
