use crate::{Authenticator, Error, ErrorKind, TokenRequestOptions, TokenResponse};
use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use serde::{de::Error as DeError, Deserialize, Deserializer};
use std::io::{ErrorKind as IoErrorKind, Result as IoResult};
use std::process::Output;
use tokio::process::Command;

/// An `AzureCliAuthenticator` enables authentication using the Azure CLI.
#[derive(Default)]
pub struct AzureCliAuthenticator {
    mock_output: Option<Box<dyn Fn() -> IoResult<Output> + Send + Sync>>,
}

impl AzureCliAuthenticator {
    /// Create a new Azure CLI authenticator
    pub fn new() -> AzureCliAuthenticator {
        AzureCliAuthenticator { mock_output: None }
    }

    #[cfg(test)]
    pub(crate) fn new_mock(
        output: Box<dyn Fn() -> IoResult<Output> + Send + Sync>,
    ) -> AzureCliAuthenticator {
        AzureCliAuthenticator {
            mock_output: Some(output),
        }
    }
}

#[async_trait]
impl Authenticator for AzureCliAuthenticator {
    async fn authenticate(&self, options: TokenRequestOptions) -> Result<TokenResponse, Error> {
        let resource = options.resource_uri()?;
        let tenant = options.tenant().ok_or_else(|| {
            Error::new(ErrorKind::Unknown, "Tenant not found in authorization URI")
        })?;
        let output = match &self.mock_output {
            Some(output) => output(),
            None => {
                let token_command = Command::new("az")
                    .args(&[
                        "account",
                        "get-access-token",
                        "--output",
                        "json",
                        "--resource",
                        &resource,
                        "--tenant",
                        &tenant,
                    ])
                    .output();
                token_command.await
            }
        };

        let output = &output.map_err(|e| match e.kind() {
            IoErrorKind::NotFound => Error::new(ErrorKind::Unknown, "Azure CLI not found, please install the Azure SDK and authenticate using 'az login'"),
            _ => Error::new(ErrorKind::Unknown, "Unknown error retrieving credentials from the Azure CLI"),
        })?;

        // dbg!(&output);

        match &output.status.code() {
            Some(0) => {
                let token: AzureSdkToken =
                    serde_json::from_slice(&output.stdout).map_err(|_| {
                        Error::new(ErrorKind::Unknown, "Failed to parse Azure CLI response")
                    })?;

                // dbg!(&token);
                Ok(TokenResponse {
                    access_token: token.access_token,
                    expires_on: token.expires_on,
                    token_type: token.token_type,
                })
            }
            _ => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if stderr.to_lowercase().contains("az account set")
                    || stderr.to_lowercase().contains("")
                {
                    Err(Error::new(
                        ErrorKind::Unknown,
                        "Not logged in, run 'az login' to log in",
                    ))
                } else {
                    Err(Error::new(
                        ErrorKind::Unknown,
                        format!(
                            "az account command exited with error: {}",
                            stderr.to_string()
                        ),
                    ))
                }
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AzureSdkToken {
    access_token: String,
    #[serde(deserialize_with = "timestamp_deserialize")]
    expires_on: DateTime<Utc>,
    tenant: String,
    token_type: String,
}

pub fn timestamp_deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer).and_then(|string| {
        Utc.datetime_from_str(&string, "%Y-%m-%d %H:%M:%S.%f")
            .map_err(D::Error::custom)
    })
}

#[cfg(test)]
mod tests {
    use crate::{Authenticator, AzureCliAuthenticator, Error, ErrorKind, TokenRequestOptions};
    use std::process::{ExitStatus, Output};

    use std::io::ErrorKind as IoErrorKind;
    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;
    #[cfg(windows)]
    use std::os::windows::process::ExitStatusExt;

    const TOKEN_RESPONSE: &'static [u8] = b"{\n\"accessToken\": \"eyJ\",\n\"expiresOn\": \"2020-06-05 08:15:30.000000\",\n\"tenant\": \"6e25f1d8-895f-4b53-8645-ae0cd5303764\",\n\"tokenType\": \"Bearer\"\n}";
    const NOT_LOGGED_IN_ERROR: &'static [u8] =
        b"No subscription found. Run 'az account set' to select a subscription.";

    fn get_token_request_options() -> TokenRequestOptions {
        TokenRequestOptions::from_resource_uri(
            "https://resource.net",
            "https://login.windows.net/6e25f1d8-895f-4b53-8645-ae0cd5303764",
        )
    }

    #[tokio::test]
    async fn azure_cli_authenticator() {
        let authenticator = AzureCliAuthenticator::new_mock(Box::new(|| {
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stderr: b"".to_vec(),
                stdout: TOKEN_RESPONSE.to_vec(),
            })
        }));

        let authentication_response = authenticator
            .authenticate(get_token_request_options())
            .await
            .unwrap();
        assert_eq!(authentication_response.access_token, "eyJ".to_string());
    }

    #[tokio::test]
    async fn azure_cli_authenticator_cli_not_installed() {
        let authenticator = AzureCliAuthenticator::new_mock(Box::new(|| {
            Err(std::io::Error::new(
                IoErrorKind::NotFound,
                Error::new(ErrorKind::Unknown, ""),
            ))
        }));

        authenticator
            .authenticate(get_token_request_options())
            .await
            .expect_err("Expected Azure CLI not found error");
    }

    #[tokio::test]
    async fn azure_cli_authenticator_not_logged_in() {
        let authenticator = AzureCliAuthenticator::new_mock(Box::new(|| {
            Ok(Output {
                status: ExitStatus::from_raw(1),
                stderr: NOT_LOGGED_IN_ERROR.to_vec(),
                stdout: b"".to_vec(),
            })
        }));

        authenticator
            .authenticate(get_token_request_options())
            .await
            .expect_err("Expected Azure CLI not logged in error");
    }
}
