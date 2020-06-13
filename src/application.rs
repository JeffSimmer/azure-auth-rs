use crate::util::{auth_request, HttpSend, HttpSender};
use crate::{Authenticator, Error, TokenRequestOptions, TokenResponse};
use async_trait::async_trait;
use std::sync::Arc;

/// An `ApplicationAuthenticator` enables authentication using an Azure Active Directory application.
pub struct ApplicationAuthenticator {
    client_id: String,
    client_secret: String,
    client: reqwest::Client,
    sender: Arc<Box<dyn HttpSend + Send + Sync>>,
}

impl ApplicationAuthenticator {
    /// Create a new application authenticator
    pub fn new(client_id: String, client_secret: String) -> ApplicationAuthenticator {
        ApplicationAuthenticator {
            client_id,
            client_secret,
            client: reqwest::Client::new(),
            sender: Arc::new(Box::new(HttpSender {})),
        }
    }

    #[cfg(test)]
    pub(crate) fn new_mock<T: 'static + HttpSend + Send + Sync>(
        client_id: String,
        client_secret: String,
        sender: T,
    ) -> ApplicationAuthenticator {
        ApplicationAuthenticator {
            client_id,
            client_secret,
            client: reqwest::Client::new(),
            sender: Arc::new(Box::new(sender)),
        }
    }
}

#[async_trait]
impl Authenticator for ApplicationAuthenticator {
    async fn authenticate(&self, options: TokenRequestOptions) -> Result<TokenResponse, Error> {
        let resource = options.resource_uri()?;
        let authorization_uri = options.authorization_uri();

        let request = self
            .client
            .post(&format!("{}/oauth2/token", &authorization_uri))
            .form(&[
                ("resource", resource),
                ("client_id", self.client_id.clone()),
                ("client_secret", self.client_secret.clone()),
                ("grant_type", "client_credentials".to_string()),
            ]);

        let sender = self.sender.clone();
        auth_request(sender, request).await
    }
}

#[cfg(test)]
mod tests {
    use crate::util::test::*;
    use crate::{ApplicationAuthenticator, Authenticator};

    const MOCK_CLIENT_ID: &'static str = "f4ae306e-eaac-4bba-9f00-c815ea207881";
    const MOCK_CLIENT_SECRET: &'static str = "secret";

    #[tokio::test]
    async fn application_authenticator() {
        let authenticator = ApplicationAuthenticator::new_mock(
            MOCK_CLIENT_ID.to_string(),
            MOCK_CLIENT_SECRET.to_string(),
            successful_token_sender(token_response()),
        );

        let authentication_response = authenticator
            .authenticate(get_token_request_options())
            .await
            .expect("Expected successful response");
        assert_eq!(
            authentication_response.access_token,
            token_response().access_token
        );
        assert_eq!(
            authentication_response.token_type,
            token_response().token_type
        );
        assert_eq!(
            authentication_response.expires_on,
            token_response().expires_on
        );
    }
}
