pub mod client;
pub mod errors;
pub mod messages;
pub mod network;
mod serialize;
pub mod server;

#[cfg(test)]
mod test {
    use crate::client::{LoginInfo, SOCKSv5Client};
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

            if let Err(e) = &client {
                println!("client result: {:?}", e);
            }
            assert!(client.is_ok());
        })
    }
}
