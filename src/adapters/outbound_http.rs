use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, Response, StatusCode};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;

pub(crate) type HttpClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

pub(crate) fn build_client() -> Result<HttpClient, String> {
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .map_err(|error| format!("failed to load native TLS roots: {error}"))?
        .https_or_http()
        .enable_http1()
        .build();
    Ok(Client::builder(TokioExecutor::new()).build(connector))
}

pub(crate) async fn request_bytes(
    client: &HttpClient,
    request: Request<Full<Bytes>>,
    max_response_bytes: usize,
) -> Result<Bytes, String> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let response = client
            .request(request)
            .await
            .map_err(|error| format!("outbound HTTP request failed: {error}"))?;
        require_success(&response)?;
        Limited::new(response.into_body(), max_response_bytes)
            .collect()
            .await
            .map(|body| body.to_bytes())
            .map_err(|error| format!("outbound HTTP response body failed: {error}"))
    })
    .await
    .map_err(|_| "outbound HTTP request timed out".to_owned())?
}

fn require_success<B>(response: &Response<B>) -> Result<(), String> {
    if response.status().is_success() {
        return Ok(());
    }
    let status = response.status();
    let reason = if status.is_redirection() {
        "redirects are not followed"
    } else if status == StatusCode::TOO_MANY_REQUESTS {
        "remote service rate limited the request"
    } else {
        "remote service returned an error"
    };
    Err(format!("{reason}: HTTP {status}"))
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use hyper::Response;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_rustls::HttpsConnectorBuilder;
    use hyper_util::rt::TokioIo;
    use rcgen::generate_simple_self_signed;
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::*;

    #[tokio::test]
    async fn ring_client_completes_a_real_tls_handshake() {
        let generated = generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let certificate = generated.cert.der().clone();
        let private_key = PrivatePkcs8KeyDer::from(generated.key_pair.serialize_der());
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], private_key.into())
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let stream = TlsAcceptor::from(std::sync::Arc::new(server_config))
                .accept(stream)
                .await
                .unwrap();
            http1::Builder::new()
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(|_| async {
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"tls-ok"))))
                    }),
                )
                .await
                .unwrap();
        });

        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).unwrap();
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_only()
            .enable_http1()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(connector);
        let request = Request::get(format!("https://localhost:{}/", address.port()))
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert_eq!(request_bytes(&client, request, 64).await.unwrap(), "tls-ok");
        drop(client);
        server.await.unwrap();
    }
}
