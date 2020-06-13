//! A library for Azure authentication
//!
//! Currently supported authentication mechanisms are
//!
//! - AzureCLI - obtain tokens from a logged-in Azure CLI
//! - ManagedIdentity - obtain tokens from an Azure VM's managed identity or from Cloud Shell
//! - UserPassword - authenticate using a username and password
//! - Application - authenticate using an application ID and secret

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod azure_cli;
pub use crate::azure_cli::AzureCliAuthenticator;
pub mod application;
pub use crate::application::ApplicationAuthenticator;
pub mod managed_identity;
pub use crate::managed_identity::ManagedIdentityAuthenticator;
pub mod user_password;
pub use crate::user_password::UserPasswordAuthenticator;
pub mod error;
pub use crate::error::{Error, ErrorKind};
mod util;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Credential {
    Application(ApplicationCredential),
    UserPassword(UserPasswordCredential),
    AzureSdk,
    ManagedService,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ApplicationCredential {
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UserPasswordCredential {
    pub client_id: String,
    pub username: String,
    pub password: String,
}

/// Trait for asynchronous Azure Active Directory authentication
///
/// Implementations of this trait can be used to obtain JWT tokens for authentication to Azure services.
#[async_trait]
pub trait Authenticator {
    /// Asynchronously obtain an authentication token
    async fn authenticate(&self, options: TokenRequestOptions) -> Result<TokenResponse, Error>;
}

impl dyn Authenticator {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(cred: Credential) -> Box<dyn Authenticator + Send> {
        match cred {
            Credential::Application(cred) => Box::new(ApplicationAuthenticator::new(
                cred.client_id,
                cred.client_secret,
            )),
            Credential::UserPassword(cred) => Box::new(UserPasswordAuthenticator::new(
                cred.client_id,
                cred.username,
                cred.password,
            )),
            Credential::AzureSdk => Box::new(AzureCliAuthenticator::new()),
            Credential::ManagedService => Box::new(ManagedIdentityAuthenticator::new()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenRequestOptions {
    scopes: Vec<String>,
    authorization_uri: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_on: DateTime<Utc>,
    pub token_type: String,
}

impl TokenRequestOptions {
    const DEFAULT_SUFFIX: &'static str = "/.default";
    pub fn from_resource_uri(resource_uri: &str, authorization_uri: &str) -> TokenRequestOptions {
        let scopes = vec![format!(
            "{}{}",
            resource_uri,
            TokenRequestOptions::DEFAULT_SUFFIX
        )];

        TokenRequestOptions {
            scopes,
            authorization_uri: authorization_uri.to_string(),
        }
    }

    pub fn resource_uri(&self) -> Result<String, Error> {
        if self.scopes.len() != 1 {
            Err(Error::new(
                ErrorKind::Unknown,
                "Resource URI requires exactly one scope",
            ))
        } else {
            let resource_uri = self.scopes[0].trim_end_matches(TokenRequestOptions::DEFAULT_SUFFIX);
            Ok(resource_uri.to_string())
        }
    }

    pub fn authorization_uri(&self) -> String {
        self.authorization_uri.clone()
    }

    pub fn tenant(&self) -> Option<String> {
        self.authorization_uri
            .split('/')
            .filter(|seg| !seg.is_empty())
            .map(|seg| seg.to_string())
            .last()
    }
}
