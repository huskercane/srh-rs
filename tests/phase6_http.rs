use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use bytes::Bytes;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use srh_rs::AppState;
use srh_rs::adapters::auth_chain::AuthChain;
use srh_rs::adapters::jwt_auth::JwtAuth;
use srh_rs::adapters::static_auth::StaticAuth;
use srh_rs::config::Config;
use srh_rs::domain::identity::{CachedKey, IntrospectError, JwksError, JwtAlgorithm};
use srh_rs::domain::rate_limit::RateLimiter;
use srh_rs::domain::resp::{AcquireError, ExecError, PoolReadiness, RespValue};
use srh_rs::ports::{
    Authenticator, Clock, CommandExecutor, ExecutorHandle, ExecutorProvider, Introspector,
    JwksSource, RedisCommand,
};
use tower::ServiceExt;

const PRIVATE_KEY: &[u8] = include_bytes!("fixtures/rsa_private.pem");
const MODULUS: &str = "yRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4l4sggh5_CYYi_cvI-SXVT9kPWSKXxJXBXd_4LkvcPuUakBoAkfh-eiFVMh2VrUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG_AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBIMc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi-yUod-j8MtvIj812dkS4QMiRVN_by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQ";

struct ClockNow;

impl Clock for ClockNow {
    fn unix_secs(&self) -> u64 {
        jsonwebtoken::get_current_timestamp()
    }

    fn instant(&self) -> Instant {
        Instant::now()
    }
}

struct Executor;

#[async_trait]
impl CommandExecutor for Executor {
    async fn execute(&self, _command: RedisCommand) -> Result<RespValue, ExecError> {
        Ok(RespValue::Simple("OK".to_owned()))
    }

    async fn pipeline(&self, commands: Vec<RedisCommand>) -> Vec<Result<RespValue, ExecError>> {
        vec![Ok(RespValue::Simple("OK".to_owned())); commands.len()]
    }

    async fn transaction(&self, commands: Vec<RedisCommand>) -> Result<Vec<RespValue>, ExecError> {
        Ok(vec![RespValue::Simple("OK".to_owned()); commands.len()])
    }
}

struct Provider;

#[async_trait]
impl ExecutorProvider for Provider {
    async fn acquire(&self, _pool: &str) -> Result<ExecutorHandle, AcquireError> {
        Ok(ExecutorHandle::new(Arc::new(Executor), Box::new(())))
    }

    async fn readiness(&self) -> Vec<PoolReadiness> {
        Vec::new()
    }
}

fn config() -> Arc<Config> {
    Arc::new(
        Config::from_json(
            r#"{
                "auth":{
                    "jwt":{"issuer":"https://issuer.test/realms/test","audience":"srh","client_id":"srh"},
                    "static_tokens":{"break-glass":{"pool":"default","allowed_commands":["GET"]}}
                },
                "pools":{"default":{"connection_string":"redis://localhost:6379"}}
            }"#,
        )
        .unwrap(),
    )
}

struct TestJwks(HashMap<String, CachedKey>);

#[async_trait]
impl JwksSource for TestJwks {
    async fn key_for(&self, kid: &str) -> Result<CachedKey, JwksError> {
        self.0.get(kid).cloned().ok_or(JwksError::NotFound)
    }
}

fn jwks() -> Arc<dyn JwksSource> {
    Arc::new(TestJwks(HashMap::from([(
        "test-key".to_owned(),
        CachedKey {
            algorithm: JwtAlgorithm::Rs256,
            material: Bytes::from(
                serde_json::to_vec(&json!({
                    "kty":"RSA", "kid":"test-key", "use":"sig", "alg":"RS256",
                    "n":MODULUS, "e":"AQAB"
                }))
                .unwrap(),
            ),
        },
    )])))
}

fn app(introspector: Option<Arc<dyn Introspector>>) -> axum::Router {
    let config = config();
    let clock: Arc<dyn Clock> = Arc::new(ClockNow);
    let jwt: Arc<dyn Authenticator> = Arc::new(JwtAuth::new(
        config.auth.jwt.clone().unwrap(),
        &config.pools,
        jwks(),
        introspector,
        Arc::clone(&clock),
    ));
    let static_auth: Arc<dyn Authenticator> =
        Arc::new(StaticAuth::new(config.auth.static_tokens.clone()));
    srh_rs::http::router(AppState {
        provider: Arc::new(Provider),
        authenticator: Arc::new(AuthChain::new(vec![jwt, static_auth])),
        clock: Arc::clone(&clock),
        rate_limiter: Arc::new(RateLimiter::new(0, clock)),
        cfg: config,
    })
}

fn jwt(roles: &[&str]) -> String {
    let now = jsonwebtoken::get_current_timestamp();
    let claims = json!({
        "sub":"user-123", "iss":"https://issuer.test/realms/test", "exp":now + 300,
        "aud":"srh", "typ":"Bearer", "resource_access":{"srh":{"roles":roles}}
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key".to_owned());
    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(PRIVATE_KEY).unwrap(),
    )
    .unwrap()
}

async fn command(app: &axum::Router, token: &str, command: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::post("/")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(command.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn jwt_roles_and_implicit_acl_defaults_apply_end_to_end() {
    let app = app(None);
    let write = jwt(&["redis:write"]);
    assert_eq!(
        command(&app, &write, json!(["SET", "k", "v"])).await.0,
        StatusCode::OK
    );
    assert_eq!(
        command(&app, &write, json!(["FLUSHALL"])).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        command(&app, &write, json!(["KEYS", "*"])).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        command(&app, &write, json!(["SCAN", 0])).await.0,
        StatusCode::OK
    );

    let read = jwt(&["redis:read"]);
    assert_eq!(
        command(&app, &read, json!(["GET", "k"])).await.0,
        StatusCode::OK
    );
    assert_eq!(
        command(&app, &read, json!(["SET", "k", "v"])).await.0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn missing_role_is_forbidden_and_static_break_glass_still_works() {
    let app = app(None);
    let (status, body) = command(&app, &jwt(&[]), json!(["GET", "k"])).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, json!({"error":"NOPERM no redis role"}));
    assert_eq!(
        command(&app, "break-glass", json!(["GET", "k"])).await.0,
        StatusCode::OK
    );
}

struct Down;

#[async_trait]
impl Introspector for Down {
    async fn is_active(&self, _token: &str) -> Result<bool, IntrospectError> {
        Err(IntrospectError("endpoint down".to_owned()))
    }
}

#[tokio::test]
async fn introspection_outage_is_503() {
    let app = app(Some(Arc::new(Down)));
    assert_eq!(
        command(&app, &jwt(&["redis:write"]), json!(["GET", "k"]))
            .await
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

struct Activity {
    active: bool,
    calls: AtomicUsize,
}

#[async_trait]
impl Introspector for Activity {
    async fn is_active(&self, _token: &str) -> Result<bool, IntrospectError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(self.active)
    }
}

#[tokio::test]
async fn inactive_introspection_is_401_and_active_results_are_cached() {
    let inactive = Arc::new(Activity {
        active: false,
        calls: AtomicUsize::new(0),
    });
    let inactive_port: Arc<dyn Introspector> = inactive.clone();
    let token = jwt(&["redis:write"]);
    assert_eq!(
        command(&app(Some(inactive_port)), &token, json!(["GET", "k"]))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(inactive.calls.load(Ordering::Relaxed), 1);

    let active = Arc::new(Activity {
        active: true,
        calls: AtomicUsize::new(0),
    });
    let active_port: Arc<dyn Introspector> = active.clone();
    let app = app(Some(active_port));
    assert_eq!(
        command(&app, &token, json!(["GET", "k"])).await.0,
        StatusCode::OK
    );
    assert_eq!(
        command(&app, &token, json!(["GET", "k"])).await.0,
        StatusCode::OK
    );
    assert_eq!(active.calls.load(Ordering::Relaxed), 1);
}
