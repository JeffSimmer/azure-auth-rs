use keyvault_agent_azure_auth::*;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let authentication_uri = "https://login.windows.net/{tenant}";
    let resource_uri = "https://vault.azure.net";

    let authenticator = ManagedIdentityAuthenticator::new();

    println!("Authenticating...");
    let auth_response = authenticator
        .authenticate(TokenRequestOptions::from_resource_uri(
            resource_uri,
            authentication_uri,
        ))
        .await;
    println!("Auth response: {:?}\n", auth_response);

    let authenticator = AzureCliAuthenticator::new();

    println!("Authenticating...");
    let auth_response = authenticator
        .authenticate(TokenRequestOptions::from_resource_uri(
            resource_uri,
            authentication_uri,
        ))
        .await;
    println!("Auth response: {:?}\n", auth_response);

    let client_id = "".to_string();
    let client_secret = "".to_string();
    let authenticator = ApplicationAuthenticator::new(client_id, client_secret);

    println!("Authenticating...");
    let auth_response = authenticator
        .authenticate(TokenRequestOptions::from_resource_uri(
            resource_uri,
            authentication_uri,
        ))
        .await;
    println!("Auth response: {:?}\n", auth_response);

    let client_id = "1950a258-227b-4e31-a9cf-717495945fc2".to_string();
    let username = "".to_string();
    let password = "".to_string();
    let authenticator = UserPasswordAuthenticator::new(client_id, username, password);

    println!("Authenticating...");
    let auth_response = authenticator
        .authenticate(TokenRequestOptions::from_resource_uri(
            resource_uri,
            authentication_uri,
        ))
        .await;
    println!("Auth response: {:?}\n", auth_response);

    Ok(())
}
