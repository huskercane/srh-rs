use async_trait::async_trait;
use base64::Engine;
use bytes::Bytes;
use http_body_util::Full;
use hyper::header::{AUTHORIZATION, CONTENT_TYPE};
use hyper::{Method, Request};
use serde::Deserialize;
use zeroize::Zeroize;

use crate::config::SecretString;
use crate::domain::identity::IntrospectError;
use crate::ports::Introspector;

use super::outbound_http::{HttpClient, build_client, request_bytes};

const INTROSPECTION_LIMIT: usize = 64 * 1024;

#[derive(Deserialize)]
struct IntrospectionResponse {
    active: bool,
}

/// Hyper/rustls RFC 7662 client using HTTP Basic client authentication.
pub struct HttpIntrospector {
    url: String,
    authorization: SecretString,
    client: HttpClient,
}

impl HttpIntrospector {
    /// Creates an RFC 7662 client with HTTP Basic client credentials.
    pub fn new(
        url: String,
        client_id: &str,
        client_secret: &SecretString,
    ) -> Result<Self, IntrospectError> {
        let parsed = url::Url::parse(&url)
            .map_err(|error| IntrospectError(format!("invalid introspection URL: {error}")))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(IntrospectError(
                "introspection URL must use http or https".to_owned(),
            ));
        }
        let mut credentials = format!("{client_id}:{}", client_secret.expose());
        let mut encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
        let authorization = format!("Basic {encoded}");
        credentials.zeroize();
        encoded.zeroize();
        Ok(Self {
            url,
            authorization: SecretString::new(authorization),
            client: build_client().map_err(IntrospectError)?,
        })
    }
}

#[async_trait]
impl Introspector for HttpIntrospector {
    async fn is_active(&self, token: &str) -> Result<bool, IntrospectError> {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("token", token)
            .finish();
        let request = Request::builder()
            .method(Method::POST)
            .uri(&self.url)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, self.authorization.expose())
            .body(Full::new(Bytes::from(body)))
            .map_err(|error| IntrospectError(format!("invalid introspection request: {error}")))?;
        let response = request_bytes(&self.client, request, INTROSPECTION_LIMIT)
            .await
            .map_err(IntrospectError)?;
        serde_json::from_slice::<IntrospectionResponse>(&response)
            .map(|response| response.active)
            .map_err(|error| IntrospectError(format!("invalid introspection response: {error}")))
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    #[tokio::test]
    async fn posts_form_encoded_token_with_client_credentials() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/introspect"))
            .and(header("authorization", "Basic Y2xpZW50OnNlY3JldA=="))
            .and(header("content-type", "application/x-www-form-urlencoded"))
            .and(body_string_contains("token=a%2Bb"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "active":true
            })))
            .expect(1)
            .mount(&server)
            .await;
        let adapter = HttpIntrospector::new(
            format!("{}/introspect", server.uri()),
            "client",
            &SecretString::new("secret".to_owned()),
        )
        .unwrap();
        assert!(adapter.is_active("a+b").await.unwrap());
    }
}
