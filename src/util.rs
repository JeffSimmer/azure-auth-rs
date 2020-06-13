use crate::{Error, TokenResponse};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::RequestBuilder;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// HttpSend trait based on the following blog post
/// https://write.as/balrogboogie/testing-reqwest-based-clients
#[async_trait]
pub(crate) trait HttpSend {
    async fn send(&self, request: RequestBuilder) -> Result<reqwest::Response, crate::Error>;
}

pub(crate) struct HttpSender;
#[async_trait]
impl HttpSend for HttpSender {
    async fn send(&self, request: RequestBuilder) -> Result<reqwest::Response, crate::Error> {
        request.send().await.map_err(|err| err.into())
    }
}

#[cfg(test)]
pub(crate) struct MockSender {
    sender: Box<dyn Fn(RequestBuilder) -> Result<reqwest::Response, crate::Error> + Send + Sync>,
}

#[cfg(test)]
impl MockSender {
    pub fn new<
        S: 'static + Fn(RequestBuilder) -> Result<reqwest::Response, crate::Error> + Send + Sync,
    >(
        sender: S,
    ) -> MockSender {
        MockSender {
            sender: Box::new(sender),
        }
    }
}

#[cfg(test)]
#[async_trait]
impl HttpSend for MockSender {
    async fn send(&self, request: RequestBuilder) -> Result<reqwest::Response, crate::Error> {
        (self.sender)(request)
    }
}

pub(crate) async fn auth_request(
    sender: Arc<Box<dyn HttpSend + Send + Sync>>,
    request_builder: RequestBuilder,
) -> Result<TokenResponse, Error> {
    auth_request_inner(sender, request_builder, |error_response: TokenRestError| {
        Error::new(crate::ErrorKind::Unknown, error_response.error_description)
    })
    .await
}

pub(crate) async fn managed_auth_request(
    sender: Arc<Box<dyn HttpSend + Send + Sync>>,
    request_builder: RequestBuilder,
) -> Result<TokenResponse, Error> {
    auth_request_inner(
        sender,
        request_builder,
        |error_response: ManagedIdentityError| {
            Error::new(crate::ErrorKind::Unknown, error_response.error.message)
        },
    )
    .await
}

async fn auth_request_inner<'a, T>(
    sender: Arc<Box<dyn HttpSend + Send + Sync>>,
    request_builder: RequestBuilder,
    error_fn: fn(T) -> Error,
) -> Result<TokenResponse, Error>
where
    T: DeserializeOwned,
{
    let response: reqwest::Response = sender.send(request_builder).await?;

    match response.status().as_u16() {
        200..=299 => {
            let token: TokenRestResponse = response.json::<TokenRestResponse>().await?;

            Ok(TokenResponse {
                access_token: token.access_token,
                expires_on: token.expires_on,
                token_type: token.token_type,
            })
        }
        _ => {
            let error_response: T = response.json().await?;

            Err(error_fn(error_response))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct TokenRestResponse {
    pub access_token: String,
    #[serde(with = "timestamp")]
    pub expires_on: DateTime<Utc>,
    pub token_type: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct TokenRestError {
    pub error: String,
    pub error_description: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct ManagedIdentityError {
    pub error: ManagedIdentityErrorInner,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct ManagedIdentityErrorInner {
    pub code: String,
    pub message: String,
}

pub mod timestamp {
    use chrono::{DateTime, NaiveDateTime, Utc};
    use serde::de::Deserializer;
    use serde::ser::Serializer;
    use serde::Deserialize;
    pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).and_then(|ts| {
            Ok(DateTime::from_utc(
                NaiveDateTime::from_timestamp(
                    ts.parse().map_err(|_| {
                        serde::de::Error::custom("unable to parse time string as an int64")
                    })?,
                    0,
                ),
                Utc,
            ))
        })
    }

    pub fn serialize<S>(dt: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&dt.timestamp().to_string())
    }
}

#[cfg(test)]
pub(crate) mod test {
    use crate::util::{MockSender, TokenRestResponse};
    use crate::TokenRequestOptions;
    use chrono::{DateTime, NaiveDateTime, Utc};

    pub(crate) fn token_response() -> TokenRestResponse {
        TokenRestResponse {
            access_token: "eyJ".to_string(),
            expires_on: DateTime::from_utc(NaiveDateTime::from_timestamp(1591826158, 0), Utc),
            token_type: "Bearer".to_string(),
        }
    }

    pub(crate) fn successful_token_sender(response: TokenRestResponse) -> MockSender {
        MockSender::new(move |_| {
            Ok(http::Response::builder()
                .status(200)
                .body(serde_json::to_string(&response).unwrap())
                .map(|resp| resp.into())
                .unwrap())
        })
    }

    pub(crate) fn get_token_request_options() -> TokenRequestOptions {
        TokenRequestOptions::from_resource_uri(
            "https://resource.net",
            "https://login.windows.net/6e25f1d8-895f-4b53-8645-ae0cd5303764",
        )
    }
}
