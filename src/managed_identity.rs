use crate::util::{managed_auth_request, HttpSend, HttpSender};
use crate::{Authenticator, Error, TokenRequestOptions, TokenResponse};
use async_trait::async_trait;
use reqwest::RequestBuilder;
use std::env;
use std::sync::Arc;

/// A `ManagedIdentityAuthenticator` enables authentication using a managed identity.
pub struct ManagedIdentityAuthenticator {
    client: reqwest::Client,
    sender: Arc<Box<dyn HttpSend + Send + Sync>>,
}

impl ManagedIdentityAuthenticator {
    pub fn new() -> ManagedIdentityAuthenticator {
        ManagedIdentityAuthenticator {
            client: reqwest::Client::new(),
            sender: Arc::new(Box::new(HttpSender {})),
        }
    }

    #[cfg(test)]
    pub(crate) fn new_mock<T: 'static + HttpSend + Send + Sync>(
        sender: T,
    ) -> ManagedIdentityAuthenticator {
        ManagedIdentityAuthenticator {
            client: reqwest::Client::new(),
            sender: Arc::new(Box::new(sender)),
        }
    }

    fn app_service_request(
        &self,
        endpoint: String,
        secret: String,
        options: TokenRequestOptions,
    ) -> Result<RequestBuilder, Error> {
        Ok(self
            .client
            .get(&endpoint)
            .query(&[
                ("api-version", "2017-09-01"),
                ("resource", &options.resource_uri()?),
            ])
            .header("secret", secret))
    }

    fn cloud_shell_request(
        &self,
        endpoint: String,
        options: TokenRequestOptions,
    ) -> Result<RequestBuilder, Error> {
        Ok(self
            .client
            .get(&endpoint)
            .query(&[
                ("api-version", "2018-02-01"),
                ("resource", &options.resource_uri()?),
            ])
            .header("Metadata", "true"))
    }

    fn imds_request(&self, options: TokenRequestOptions) -> Result<RequestBuilder, Error> {
        Ok(self
            .client
            .get("http://169.254.169.254/metadata/identity/oauth2/token")
            .query(&[
                ("api-version", "2018-02-01"),
                ("resource", &options.resource_uri()?),
            ])
            .header("Metadata", "true"))
    }
}

impl Default for ManagedIdentityAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Authenticator for ManagedIdentityAuthenticator {
    async fn authenticate(&self, options: TokenRequestOptions) -> Result<TokenResponse, Error> {
        let msi_endpoint = env::var("MSI_ENDPOINT").ok();
        let msi_secret = env::var("MSI_SECRET").ok();

        let request = match (msi_endpoint, msi_secret) {
            (Some(endpoint), Some(secret)) => self.app_service_request(endpoint, secret, options),
            (Some(endpoint), None) => self.cloud_shell_request(endpoint, options),
            _ => self.imds_request(options),
        }?;

        let sender = self.sender.clone();
        managed_auth_request(sender, request).await
    }
}

#[cfg(test)]
mod tests {
    use crate::util::test::*;
    use crate::{Authenticator, ManagedIdentityAuthenticator};

    // Example error
    // {"error":{"code":"invalid_request","message":"Required audience parameter not specified"}}

    #[tokio::test]
    async fn managed_identity_authenticator() {
        let authenticator =
            ManagedIdentityAuthenticator::new_mock(successful_token_sender(token_response()));

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
