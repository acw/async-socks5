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
    use crate::network::testing::TestingStack;
    use crate::server::{SOCKSv5Server, SecurityParameters};
    use async_std::task;

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
}
