use std::collections::{HashMap, HashSet};
use std::fmt::{self, Debug, Formatter};
use std::fs;
use std::path::Path;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

const DEFAULT_CONFIG_PATH: &str = "./srh-config/tokens.json";

#[derive(Clone, Eq, PartialEq)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Debug for SecretString {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("\"<redacted>\"")
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub server: ServerConfig,
    pub auth: AuthConfig,
    pub pools: HashMap<String, PoolConfig>,
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub port: u16,
    pub bind: String,
    pub tls: Option<TlsConfig>,
    pub max_body_bytes: usize,
    pub max_pipeline_commands: usize,
    pub max_request_elements: usize,
    pub http_timeout_ms: u64,
    pub rate_limit: RateLimitConfig,
    pub load: LoadConfig,
    pub metrics_bind: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub cert: String,
    pub key: String,
}

#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    pub per_token_commands_per_sec: u64,
}

#[derive(Clone, Debug)]
pub struct LoadConfig {
    pub max_in_flight: usize,
    pub max_response_bytes: usize,
    pub shed_retry_after_secs: u64,
    pub body_read_timeout_ms: u64,
}

#[derive(Clone, Debug, Default)]
pub struct AuthConfig {
    pub jwt: Option<JwtConfig>,
    pub static_tokens: HashMap<[u8; 32], StaticTokenConfig>,
}

#[derive(Clone, Debug)]
pub struct JwtConfig {
    pub issuer: String,
    pub audience: String,
    pub jwks_refresh_secs: u64,
    pub role_prefix: String,
    pub client_id: String,
    pub introspection: IntrospectionConfig,
}

#[derive(Clone, Debug)]
pub struct IntrospectionConfig {
    pub enabled: bool,
    pub url: String,
    pub client_id: String,
    pub client_secret: SecretString,
    pub cache_secs: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticTokenConfig {
    pub pool: String,
    pub read_only: bool,
    pub legacy: bool,
    pub allowed_commands: Option<HashSet<String>>,
    pub blocked_commands: HashSet<String>,
    pub allowed_script_sha256: HashSet<String>,
    pub key_prefix: Option<String>,
}

#[derive(Clone, Debug)]
pub struct PoolConfig {
    pub connection_string: SecretString,
    pub max_connections: usize,
    pub command_timeout_ms: u64,
    pub acquire_timeout_ms: u64,
    pub max_waiters: usize,
    pub breaker: BreakerConfig,
    // Server-controlled widening policy copied into every identity routed to this pool.
    pub allowed_script_sha256: HashSet<String>,
    // Server-controlled narrowing floor applied to every identity routed to this pool.
    pub key_prefix: Option<String>,
}

#[derive(Clone, Debug)]
pub struct BreakerConfig {
    pub failure_threshold: usize,
    pub cooldown_ms: u64,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read configuration at {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("invalid configuration JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("missing required environment variable {0}")]
    MissingEnvironment(&'static str),
    #[error("invalid environment variable {name}: {reason}")]
    InvalidEnvironment { name: &'static str, reason: String },
    #[error("invalid configuration: {0}")]
    Validation(String),
}

impl Config {
    pub fn load() -> Result<Self, ConfigError> {
        Self::from_environment(|name| std::env::var(name).ok())
    }

    pub fn from_environment(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let mode = get("SRH_MODE").unwrap_or_else(|| "file".to_owned());
        let mut config = match mode.as_str() {
            "env" => Self::from_env_mode(&get)?,
            "file" => {
                let path = get("SRH_CONFIG_PATH").unwrap_or_else(|| DEFAULT_CONFIG_PATH.to_owned());
                Self::from_path(path)?
            }
            _ => {
                return Err(ConfigError::InvalidEnvironment {
                    name: "SRH_MODE",
                    reason: "expected `file` or `env`".to_owned(),
                });
            }
        };
        config.apply_server_overrides(&get)?;
        config.validate()?;
        Ok(config)
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let json = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_json(&json)
    }

    pub fn from_json(json: &str) -> Result<Self, ConfigError> {
        let value: serde_json::Value = serde_json::from_str(json)?;
        let is_legacy = value
            .as_object()
            .is_some_and(|entries| entries.values().any(has_connection_string));
        let config = if is_legacy {
            Self::from_legacy_value(value)?
        } else {
            Self::from_new_value(value)?
        };
        config.validate()?;
        Ok(config)
    }

    fn from_env_mode(get: &impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let token = required(get, "SRH_TOKEN")?;
        let connection_string = required(get, "SRH_CONNECTION_STRING")?;
        let max_connections = parse_env(get, "SRH_MAX_CONNECTIONS")?.unwrap_or(3);
        let digest = digest_token(&token);
        drop(token);

        let mut static_tokens = HashMap::new();
        // Environment mode is the original SRH deployment interface. Keep its single token on
        // the legacy policy so the documented Docker command retains FLUSH/KEYS compatibility.
        static_tokens.insert(digest, default_token("default", true));
        let mut pools = HashMap::new();
        pools.insert(
            "default".to_owned(),
            PoolConfig::new(connection_string, max_connections, 2_000, 500, None, None),
        );
        Ok(Self {
            server: ServerConfig::default(),
            auth: AuthConfig {
                jwt: None,
                static_tokens,
            },
            pools,
        })
    }

    fn from_legacy_value(value: serde_json::Value) -> Result<Self, ConfigError> {
        let entries: HashMap<String, RawLegacyToken> = serde_json::from_value(value)?;
        let mut static_tokens = HashMap::new();
        let mut pools = HashMap::new();
        for (token, entry) in entries {
            let digest = digest_token(&token);
            drop(token);
            let pool = entry
                .srh_id
                .filter(|id| !id.is_empty())
                .unwrap_or_else(|| digest_prefix(&digest));
            let candidate = PoolConfig::new(
                entry.connection_string,
                entry.max_connections,
                2_000,
                500,
                None,
                None,
            );
            if let Some(existing) = pools.get(&pool) {
                if !same_legacy_pool(existing, &candidate) {
                    return Err(ConfigError::Validation(format!(
                        "legacy srh_id '{pool}' has conflicting pool definitions"
                    )));
                }
            } else {
                pools.insert(pool.clone(), candidate);
            }
            static_tokens.insert(digest, default_token(&pool, true));
        }
        Ok(Self {
            server: ServerConfig::default(),
            auth: AuthConfig {
                jwt: None,
                static_tokens,
            },
            pools,
        })
    }

    fn from_new_value(value: serde_json::Value) -> Result<Self, ConfigError> {
        let raw: RawConfig = serde_json::from_value(value)?;
        let mut static_tokens = HashMap::new();
        for (token, entry) in raw.auth.static_tokens {
            let digest = parse_configured_digest(&token)?;
            drop(token);
            static_tokens.insert(
                digest,
                StaticTokenConfig {
                    pool: entry.pool,
                    read_only: entry.read_only,
                    legacy: false,
                    allowed_commands: entry.allowed_commands.map(uppercase_set),
                    blocked_commands: uppercase_set(entry.blocked_commands),
                    allowed_script_sha256: entry
                        .allowed_script_sha256
                        .into_iter()
                        .map(|value| value.to_ascii_lowercase())
                        .collect(),
                    key_prefix: entry.key_prefix,
                },
            );
        }

        let pools: HashMap<String, PoolConfig> = raw
            .pools
            .into_iter()
            .map(|(name, pool)| {
                let max_waiters = pool
                    .max_waiters
                    .or_else(|| pool.max_connections.checked_mul(4));
                let allowed_script_sha256 = pool
                    .allowed_script_sha256
                    .into_iter()
                    .map(|value| value.to_ascii_lowercase())
                    .collect();
                let mut normalized = PoolConfig::new(
                    pool.connection_string,
                    pool.max_connections,
                    pool.command_timeout_ms,
                    pool.acquire_timeout_ms,
                    max_waiters,
                    Some(pool.breaker),
                );
                normalized.allowed_script_sha256 = allowed_script_sha256;
                normalized.key_prefix = pool.key_prefix;
                (name, normalized)
            })
            .collect();

        for token in static_tokens.values_mut() {
            if let Some(pool) = pools.get(&token.pool) {
                token
                    .allowed_script_sha256
                    .extend(pool.allowed_script_sha256.iter().cloned());
            }
        }

        Ok(Self {
            server: raw.server.into(),
            auth: AuthConfig {
                jwt: raw.auth.jwt.map(Into::into),
                static_tokens,
            },
            pools,
        })
    }

    fn apply_server_overrides(
        &mut self,
        get: &impl Fn(&str) -> Option<String>,
    ) -> Result<(), ConfigError> {
        if let Some(bind) = get("SRH_BIND") {
            self.server.bind = bind;
        }
        if let Some(port) = parse_env(get, "SRH_PORT")? {
            self.server.port = port;
        }
        if parse_bool_env(get, "SRH_IPV6")?.unwrap_or(false) {
            if self.server.bind != "127.0.0.1" && self.server.bind != "0.0.0.0" {
                tracing::warn!(
                    bind = %self.server.bind,
                    "SRH_IPV6 overrides an explicit SRH_BIND value"
                );
            }
            self.server.bind = if self.server.bind == "0.0.0.0" {
                "::".to_owned()
            } else {
                "::1".to_owned()
            };
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_nonzero("server.port", self.server.port)?;
        validate_nonzero("server.max_body_bytes", self.server.max_body_bytes)?;
        validate_nonzero(
            "server.max_pipeline_commands",
            self.server.max_pipeline_commands,
        )?;
        validate_nonzero(
            "server.max_request_elements",
            self.server.max_request_elements,
        )?;
        validate_nonzero("server.http_timeout_ms", self.server.http_timeout_ms)?;
        validate_nonzero("server.load.max_in_flight", self.server.load.max_in_flight)?;
        validate_nonzero(
            "server.load.max_response_bytes",
            self.server.load.max_response_bytes,
        )?;
        validate_nonzero(
            "server.load.shed_retry_after_secs",
            self.server.load.shed_retry_after_secs,
        )?;
        validate_nonzero(
            "server.load.body_read_timeout_ms",
            self.server.load.body_read_timeout_ms,
        )?;
        self.server
            .metrics_bind
            .parse::<std::net::SocketAddr>()
            .map_err(|error| {
                ConfigError::Validation(format!(
                    "server.metrics_bind is not a valid socket address: {error}"
                ))
            })?;

        if let Some(jwt) = &self.auth.jwt {
            let issuer = url::Url::parse(&jwt.issuer).map_err(|error| {
                ConfigError::Validation(format!("auth.jwt.issuer is not a valid URL: {error}"))
            })?;
            if !matches!(issuer.scheme(), "http" | "https") {
                return Err(ConfigError::Validation(
                    "auth.jwt.issuer must use http or https".to_owned(),
                ));
            }
            if jwt.audience.is_empty() || jwt.client_id.is_empty() {
                return Err(ConfigError::Validation(
                    "auth.jwt.audience and auth.jwt.client_id must not be empty".to_owned(),
                ));
            }
            validate_nonzero("auth.jwt.jwks_refresh_secs", jwt.jwks_refresh_secs)?;
            if jwt.introspection.enabled {
                let endpoint = url::Url::parse(&jwt.introspection.url).map_err(|error| {
                    ConfigError::Validation(format!(
                        "auth.jwt.introspection.url is not a valid URL: {error}"
                    ))
                })?;
                if !matches!(endpoint.scheme(), "http" | "https") {
                    return Err(ConfigError::Validation(
                        "auth.jwt.introspection.url must use http or https".to_owned(),
                    ));
                }
                if jwt.introspection.client_id.is_empty()
                    || jwt.introspection.client_secret.expose().is_empty()
                {
                    return Err(ConfigError::Validation(
                        "enabled JWT introspection requires client_id and client_secret".to_owned(),
                    ));
                }
                validate_nonzero(
                    "auth.jwt.introspection.cache_secs",
                    jwt.introspection.cache_secs,
                )?;
            }
        }

        for (name, pool) in &self.pools {
            if let Some(prefix) = &pool.key_prefix {
                crate::domain::key_prefix::validate(prefix).map_err(|error| {
                    ConfigError::Validation(format!("pools.{name}.key_prefix is invalid: {error}"))
                })?;
            }
        }
        for (digest, token) in &self.auth.static_tokens {
            let Some(pool) = self.pools.get(&token.pool) else {
                return Err(ConfigError::Validation(format!(
                    "static token references missing pool '{}'",
                    token.pool
                )));
            };
            crate::domain::key_prefix::resolve(
                pool.key_prefix.as_deref(),
                token.key_prefix.as_deref(),
            )
            .map_err(|error| {
                ConfigError::Validation(format!(
                    "static token {} for pool '{}' has invalid key_prefix: {error}",
                    digest_prefix(digest),
                    token.pool
                ))
            })?;
        }
        for (name, pool) in &self.pools {
            if pool.connection_string.expose().is_empty() {
                return Err(ConfigError::Validation(format!(
                    "pools.{name}.connection_string must not be empty"
                )));
            }
            validate_nonzero(
                &format!("pools.{name}.max_connections"),
                pool.max_connections,
            )?;
            validate_nonzero(
                &format!("pools.{name}.command_timeout_ms"),
                pool.command_timeout_ms,
            )?;
            validate_nonzero(
                &format!("pools.{name}.acquire_timeout_ms"),
                pool.acquire_timeout_ms,
            )?;
            validate_nonzero(&format!("pools.{name}.max_waiters"), pool.max_waiters)?;
            validate_nonzero(
                &format!("pools.{name}.breaker.failure_threshold"),
                pool.breaker.failure_threshold,
            )?;
            validate_nonzero(
                &format!("pools.{name}.breaker.cooldown_ms"),
                pool.breaker.cooldown_ms,
            )?;
            let command_and_reset = pool.command_timeout_ms.checked_mul(2).ok_or_else(|| {
                ConfigError::Validation(format!("timeouts overflow for pool '{name}'"))
            })?;
            let total = pool
                .acquire_timeout_ms
                .checked_add(command_and_reset)
                .ok_or_else(|| {
                    ConfigError::Validation(format!("timeouts overflow for pool '{name}'"))
                })?;
            if total >= self.server.http_timeout_ms {
                return Err(ConfigError::Validation(format!(
                    "pool '{name}' requires acquire_timeout_ms + 2 * command_timeout_ms < http_timeout_ms"
                )));
            }
        }
        Ok(())
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: 80,
            bind: "127.0.0.1".to_owned(),
            tls: None,
            max_body_bytes: 10_485_760,
            max_pipeline_commands: 1_000,
            max_request_elements: 10_000,
            http_timeout_ms: 10_000,
            rate_limit: RateLimitConfig {
                per_token_commands_per_sec: 0,
            },
            load: LoadConfig {
                max_in_flight: 512,
                max_response_bytes: 33_554_432,
                shed_retry_after_secs: 1,
                body_read_timeout_ms: 2_000,
            },
            metrics_bind: "127.0.0.1:9422".to_owned(),
        }
    }
}

impl PoolConfig {
    fn new(
        connection_string: String,
        max_connections: usize,
        command_timeout_ms: u64,
        acquire_timeout_ms: u64,
        max_waiters: Option<usize>,
        breaker: Option<RawBreakerConfig>,
    ) -> Self {
        Self {
            connection_string: SecretString::new(connection_string),
            max_connections,
            command_timeout_ms,
            acquire_timeout_ms,
            max_waiters: max_waiters.unwrap_or_else(|| max_connections.saturating_mul(4)),
            breaker: breaker.unwrap_or_default().into(),
            allowed_script_sha256: HashSet::new(),
            key_prefix: None,
        }
    }
}

fn same_legacy_pool(left: &PoolConfig, right: &PoolConfig) -> bool {
    left.connection_string.expose() == right.connection_string.expose()
        && left.max_connections == right.max_connections
}

fn has_connection_string(value: &serde_json::Value) -> bool {
    value
        .as_object()
        .is_some_and(|entry| entry.contains_key("connection_string"))
}

fn required(
    get: &impl Fn(&str) -> Option<String>,
    name: &'static str,
) -> Result<String, ConfigError> {
    get(name).ok_or(ConfigError::MissingEnvironment(name))
}

fn parse_env<T: std::str::FromStr>(
    get: &impl Fn(&str) -> Option<String>,
    name: &'static str,
) -> Result<Option<T>, ConfigError>
where
    T::Err: fmt::Display,
{
    get(name)
        .map(|value| {
            value
                .parse()
                .map_err(|error: T::Err| ConfigError::InvalidEnvironment {
                    name,
                    reason: error.to_string(),
                })
        })
        .transpose()
}

fn parse_bool_env(
    get: &impl Fn(&str) -> Option<String>,
    name: &'static str,
) -> Result<Option<bool>, ConfigError> {
    get(name)
        .map(|value| match value.as_str() {
            "true" | "1" => Ok(true),
            "false" | "0" => Ok(false),
            _ => Err(ConfigError::InvalidEnvironment {
                name,
                reason: "expected true, false, 1, or 0".to_owned(),
            }),
        })
        .transpose()
}

fn validate_nonzero<T>(name: &str, value: T) -> Result<(), ConfigError>
where
    T: PartialEq + From<u8>,
{
    if value == T::from(0) {
        Err(ConfigError::Validation(format!(
            "{name} must be greater than zero"
        )))
    } else {
        Ok(())
    }
}

fn digest_token(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn parse_configured_digest(token: &str) -> Result<[u8; 32], ConfigError> {
    let Some(hex) = token.strip_prefix("sha256:") else {
        return Ok(digest_token(token));
    };
    if hex.len() != 64 {
        return Err(ConfigError::Validation(
            "sha256 token keys must contain exactly 64 hex characters".to_owned(),
        ));
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or_else(invalid_digest_hex)?;
        let low = hex_nibble(pair[1]).ok_or_else(invalid_digest_hex)?;
        digest[index] = (high << 4) | low;
    }
    Ok(digest)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn invalid_digest_hex() -> ConfigError {
    ConfigError::Validation("sha256 token keys must contain only hex".to_owned())
}

pub fn digest_hex(digest: &[u8; 32]) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn digest_prefix(digest: &[u8; 32]) -> String {
    digest_hex(digest)[..8].to_owned()
}

fn uppercase_set(values: Vec<String>) -> HashSet<String> {
    values
        .into_iter()
        .map(|value| value.to_ascii_uppercase())
        .collect()
}

fn default_token(pool: &str, legacy: bool) -> StaticTokenConfig {
    StaticTokenConfig {
        pool: pool.to_owned(),
        read_only: false,
        legacy,
        allowed_commands: None,
        blocked_commands: HashSet::new(),
        allowed_script_sha256: HashSet::new(),
        key_prefix: None,
    }
}

#[derive(Deserialize)]
struct RawLegacyToken {
    #[serde(default)]
    srh_id: Option<String>,
    connection_string: String,
    #[serde(default = "default_max_connections")]
    max_connections: usize,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawConfig {
    server: RawServerConfig,
    auth: RawAuthConfig,
    pools: HashMap<String, RawPoolConfig>,
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawServerConfig {
    port: u16,
    bind: String,
    tls: Option<TlsConfig>,
    max_body_bytes: usize,
    max_pipeline_commands: usize,
    max_request_elements: usize,
    http_timeout_ms: u64,
    rate_limit: RawRateLimitConfig,
    load: RawLoadConfig,
    metrics_bind: String,
}

impl Default for RawServerConfig {
    fn default() -> Self {
        let server = ServerConfig::default();
        Self {
            port: server.port,
            bind: server.bind,
            tls: server.tls,
            max_body_bytes: server.max_body_bytes,
            max_pipeline_commands: server.max_pipeline_commands,
            max_request_elements: server.max_request_elements,
            http_timeout_ms: server.http_timeout_ms,
            rate_limit: RawRateLimitConfig::default(),
            load: RawLoadConfig::default(),
            metrics_bind: server.metrics_bind,
        }
    }
}

impl From<RawServerConfig> for ServerConfig {
    fn from(raw: RawServerConfig) -> Self {
        Self {
            port: raw.port,
            bind: raw.bind,
            tls: raw.tls,
            max_body_bytes: raw.max_body_bytes,
            max_pipeline_commands: raw.max_pipeline_commands,
            max_request_elements: raw.max_request_elements,
            http_timeout_ms: raw.http_timeout_ms,
            rate_limit: raw.rate_limit.into(),
            load: raw.load.into(),
            metrics_bind: raw.metrics_bind,
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawRateLimitConfig {
    per_token_commands_per_sec: u64,
}

impl From<RawRateLimitConfig> for RateLimitConfig {
    fn from(raw: RawRateLimitConfig) -> Self {
        Self {
            per_token_commands_per_sec: raw.per_token_commands_per_sec,
        }
    }
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawLoadConfig {
    max_in_flight: usize,
    max_response_bytes: usize,
    shed_retry_after_secs: u64,
    body_read_timeout_ms: u64,
}

impl Default for RawLoadConfig {
    fn default() -> Self {
        let load = ServerConfig::default().load;
        Self {
            max_in_flight: load.max_in_flight,
            max_response_bytes: load.max_response_bytes,
            shed_retry_after_secs: load.shed_retry_after_secs,
            body_read_timeout_ms: load.body_read_timeout_ms,
        }
    }
}

impl From<RawLoadConfig> for LoadConfig {
    fn from(raw: RawLoadConfig) -> Self {
        Self {
            max_in_flight: raw.max_in_flight,
            max_response_bytes: raw.max_response_bytes,
            shed_retry_after_secs: raw.shed_retry_after_secs,
            body_read_timeout_ms: raw.body_read_timeout_ms,
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawAuthConfig {
    jwt: Option<RawJwtConfig>,
    static_tokens: HashMap<String, RawStaticTokenConfig>,
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawJwtConfig {
    issuer: String,
    audience: String,
    jwks_refresh_secs: u64,
    role_prefix: String,
    client_id: String,
    introspection: RawIntrospectionConfig,
}

impl Default for RawJwtConfig {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            audience: String::new(),
            jwks_refresh_secs: 600,
            role_prefix: "redis:".to_owned(),
            client_id: "srh".to_owned(),
            introspection: RawIntrospectionConfig::default(),
        }
    }
}

impl From<RawJwtConfig> for JwtConfig {
    fn from(raw: RawJwtConfig) -> Self {
        Self {
            issuer: raw.issuer,
            audience: raw.audience,
            jwks_refresh_secs: raw.jwks_refresh_secs,
            role_prefix: raw.role_prefix,
            client_id: raw.client_id,
            introspection: raw.introspection.into(),
        }
    }
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawIntrospectionConfig {
    enabled: bool,
    url: String,
    client_id: String,
    client_secret: String,
    cache_secs: u64,
}

impl Default for RawIntrospectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            cache_secs: 30,
        }
    }
}

impl From<RawIntrospectionConfig> for IntrospectionConfig {
    fn from(raw: RawIntrospectionConfig) -> Self {
        Self {
            enabled: raw.enabled,
            url: raw.url,
            client_id: raw.client_id,
            client_secret: SecretString::new(raw.client_secret),
            cache_secs: raw.cache_secs,
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawStaticTokenConfig {
    pool: String,
    read_only: bool,
    allowed_commands: Option<Vec<String>>,
    blocked_commands: Vec<String>,
    allowed_script_sha256: Vec<String>,
    key_prefix: Option<String>,
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawPoolConfig {
    connection_string: String,
    max_connections: usize,
    command_timeout_ms: u64,
    acquire_timeout_ms: u64,
    max_waiters: Option<usize>,
    breaker: RawBreakerConfig,
    allowed_script_sha256: Vec<String>,
    key_prefix: Option<String>,
}

impl Default for RawPoolConfig {
    fn default() -> Self {
        Self {
            connection_string: String::new(),
            max_connections: default_max_connections(),
            command_timeout_ms: 2_000,
            acquire_timeout_ms: 500,
            max_waiters: None,
            breaker: RawBreakerConfig::default(),
            allowed_script_sha256: Vec::new(),
            key_prefix: None,
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawBreakerConfig {
    failure_threshold: usize,
    cooldown_ms: u64,
}

impl Default for RawBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 10,
            cooldown_ms: 2_000,
        }
    }
}

impl From<RawBreakerConfig> for BreakerConfig {
    fn from(raw: RawBreakerConfig) -> Self {
        Self {
            failure_threshold: raw.failure_threshold,
            cooldown_ms: raw.cooldown_ms,
        }
    }
}

const fn default_max_connections() -> usize {
    3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_normalizes_legacy_tokens() {
        let config = Config::from_json(
            r#"{"legacy-secret":{"srh_id":"cache","connection_string":"redis://localhost:6379","max_connections":5}}"#,
        )
        .expect("legacy config should parse");
        let digest = digest_token("legacy-secret");
        let token = &config.auth.static_tokens[&digest];
        assert_eq!(token.pool, "cache");
        assert!(token.legacy);
        assert_eq!(config.pools["cache"].max_connections, 5);
    }

    #[test]
    fn parses_new_config_and_normalizes_permissions() {
        let digest = digest_hex(&digest_token("test"));
        let json = format!(
            r#"{{"auth":{{"static_tokens":{{"sha256:{digest}":{{"pool":"cache","allowed_commands":["get"],"blocked_commands":["set"]}}}}}},"pools":{{"cache":{{"connection_string":"redis://localhost:6379"}}}}}}"#
        );
        let config = Config::from_json(&json).expect("new config should parse");
        let token = &config.auth.static_tokens[&digest_token("test")];
        assert_eq!(
            token.allowed_commands.as_ref().unwrap(),
            &HashSet::from(["GET".to_owned()])
        );
        assert!(token.blocked_commands.contains("SET"));
        assert!(!token.legacy);
    }

    #[test]
    fn request_element_budget_is_independent_and_nonzero() {
        let config = Config::from_json(r#"{"server":{"max_request_elements":5001}}"#)
            .expect("request element budget should parse");
        assert_eq!(config.server.max_request_elements, 5001);
        assert_eq!(config.server.max_pipeline_commands, 1000);

        let error = Config::from_json(r#"{"server":{"max_request_elements":0}}"#)
            .expect_err("request element budget must be finite and nonzero");
        assert!(error.to_string().contains("max_request_elements"));
    }

    #[test]
    fn rejects_unknown_new_format_security_fields() {
        let error = Config::from_json(
            r#"{"auth":{"static_tokens":{"token":{"pool":"cache","read_ony":true,"blocked_comands":["FLUSHALL"]}}},"pools":{"cache":{"connection_string":"redis://localhost:6379"}}}"#,
        )
        .expect_err("security field typos must fail closed");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn legacy_entries_may_have_extra_compatibility_fields() {
        Config::from_json(
            r#"{"token":{"srh_id":"cache","connection_string":"redis://localhost:6379","historical_option":true}}"#,
        )
        .expect("legacy extras should remain compatible");
    }

    #[test]
    fn rejects_conflicting_legacy_pool_definitions() {
        let error = Config::from_json(
            r#"{"one":{"srh_id":"cache","connection_string":"redis://one:6379"},"two":{"srh_id":"cache","connection_string":"redis://two:6379"}}"#,
        )
        .expect_err("shared legacy pool names must be deterministic");
        assert!(error.to_string().contains("conflicting pool definitions"));
    }

    #[test]
    fn parses_pool_level_script_allowlist_for_phase_five() {
        let config = Config::from_json(
            r#"{"auth":{"static_tokens":{"token":{"pool":"cache","allowed_script_sha256":["1234"]}}},"pools":{"cache":{"connection_string":"redis://localhost:6379","allowed_script_sha256":["ABCDEF"]}}}"#,
        )
        .expect("pool script allowlist should parse");
        assert!(
            config.pools["cache"]
                .allowed_script_sha256
                .contains("abcdef")
        );
        let token = &config.auth.static_tokens[&digest_token("token")];
        assert!(token.allowed_script_sha256.contains("1234"));
        assert!(token.allowed_script_sha256.contains("abcdef"));
    }

    #[test]
    fn parses_pool_key_prefix_and_accepts_a_static_extension() {
        let config = Config::from_json(
            r#"{"auth":{"static_tokens":{"token":{"pool":"cache","key_prefix":"tenant:user:"}}},"pools":{"cache":{"connection_string":"redis://localhost:6379","key_prefix":"tenant:"}}}"#,
        )
        .expect("pool and token prefixes should parse");
        assert_eq!(config.pools["cache"].key_prefix.as_deref(), Some("tenant:"));
        assert_eq!(
            config.auth.static_tokens[&digest_token("token")]
                .key_prefix
                .as_deref(),
            Some("tenant:user:")
        );
    }

    #[test]
    fn rejects_invalid_pool_key_prefixes_with_the_field_name() {
        let error = Config::from_json(
            r#"{"pools":{"cache":{"connection_string":"redis://localhost:6379","key_prefix":"tenant:*"}}}"#,
        )
        .expect_err("glob metacharacters must fail closed");
        assert!(error.to_string().contains("pools.cache.key_prefix"));
    }

    #[test]
    fn rejects_static_prefixes_outside_the_pool_floor_without_exposing_the_token() {
        let error = Config::from_json(
            r#"{"auth":{"static_tokens":{"secret-token":{"pool":"cache","key_prefix":"other:"}}},"pools":{"cache":{"connection_string":"redis://localhost:6379","key_prefix":"tenant:"}}}"#,
        )
        .expect_err("a static prefix may only extend its pool floor");
        let message = error.to_string();
        assert!(message.contains("pool 'cache'"));
        assert!(message.contains(&digest_prefix(&digest_token("secret-token"))));
        assert!(!message.contains("secret-token"));
    }

    #[test]
    fn pool_key_prefix_keeps_unknown_field_validation_strict() {
        let error = Config::from_json(
            r#"{"pools":{"cache":{"connection_string":"redis://localhost:6379","key_prefix":"tenant:","key_prefx":"typo:"}}}"#,
        )
        .expect_err("a misspelled prefix field must fail closed");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn validates_jwt_and_enabled_introspection_bounds() {
        for json in [
            r#"{"auth":{"jwt":{"issuer":"https://issuer.test","audience":"","client_id":"srh"}}}"#,
            r#"{"auth":{"jwt":{"issuer":"https://issuer.test","audience":"srh","client_id":"srh","jwks_refresh_secs":0}}}"#,
            r#"{"auth":{"jwt":{"issuer":"https://issuer.test","audience":"srh","client_id":"srh","introspection":{"enabled":true,"url":"file:///secret","client_id":"client","client_secret":"secret"}}}}"#,
            r#"{"auth":{"jwt":{"issuer":"https://issuer.test","audience":"srh","client_id":"srh","introspection":{"enabled":true,"url":"https://issuer.test/introspect","client_id":"client","client_secret":"secret","cache_secs":0}}}}"#,
        ] {
            assert!(Config::from_json(json).is_err(), "must reject {json}");
        }
        Config::from_json(
            r#"{"auth":{"jwt":{"issuer":"https://issuer.test","audience":"srh","client_id":"srh","introspection":{"enabled":true,"url":"https://issuer.test/introspect","client_id":"client","client_secret":"secret","cache_secs":30}}}}"#,
        )
        .expect("complete JWT introspection configuration should validate");
    }

    #[test]
    fn env_mode_normalizes_one_pool_and_token() {
        let values = HashMap::from([
            ("SRH_MODE", "env"),
            ("SRH_TOKEN", "secret"),
            ("SRH_CONNECTION_STRING", "redis://localhost:6379"),
            ("SRH_MAX_CONNECTIONS", "7"),
        ]);
        let config = Config::from_environment(|name| values.get(name).map(ToString::to_string))
            .expect("env config should parse");
        assert_eq!(config.pools["default"].max_connections, 7);
        assert!(
            config
                .auth
                .static_tokens
                .contains_key(&digest_token("secret"))
        );
        assert!(config.auth.static_tokens[&digest_token("secret")].legacy);
    }

    #[test]
    fn plaintext_and_digest_keys_produce_the_same_lookup_key() {
        let digest = digest_hex(&digest_token("secret"));
        for key in ["secret".to_owned(), format!("sha256:{digest}")] {
            let json = format!(
                r#"{{"auth":{{"static_tokens":{{"{key}":{{"pool":"cache"}}}}}},"pools":{{"cache":{{"connection_string":"redis://localhost:6379"}}}}}}"#
            );
            let config = Config::from_json(&json).expect("token config should parse");
            assert!(
                config
                    .auth
                    .static_tokens
                    .contains_key(&digest_token("secret"))
            );
        }
    }

    #[test]
    fn rejects_a_token_that_references_a_missing_pool() {
        let error = Config::from_json(r#"{"auth":{"static_tokens":{"token":{"pool":"missing"}}}}"#)
            .expect_err("missing pool must fail");
        assert!(error.to_string().contains("missing pool"));
    }

    #[test]
    fn rejects_acquire_command_and_reset_sum_that_reaches_http_timeout() {
        let error = Config::from_json(
            r#"{"server":{"http_timeout_ms":4500},"pools":{"cache":{"connection_string":"redis://localhost:6379","acquire_timeout_ms":500,"command_timeout_ms":2000}}}"#,
        )
        .expect_err("invalid timeout ordering must fail");
        assert!(
            error
                .to_string()
                .contains("acquire_timeout_ms + 2 * command_timeout_ms")
        );
    }

    #[test]
    fn rejects_a_pool_without_a_connection_string() {
        let error = Config::from_json(r#"{"pools":{"cache":{}}}"#)
            .expect_err("connection string is required");
        assert!(error.to_string().contains("connection_string"));
    }

    #[test]
    fn secrets_are_redacted_from_debug_output() {
        let secret = SecretString::new("redis://user:password@localhost".to_owned());
        assert_eq!(format!("{secret:?}"), "\"<redacted>\"");
    }

    #[test]
    fn normalized_config_debug_contains_no_plaintext_credentials() {
        let config = Config::from_json(
            r#"{"auth":{"static_tokens":{"plain-token":{"pool":"cache"}}},"pools":{"cache":{"connection_string":"redis://user:password@localhost:6379"}}}"#,
        )
        .expect("config should parse");
        let debug = format!("{config:?}");
        assert!(!debug.contains("plain-token"));
        assert!(!debug.contains("password"));
    }

    #[test]
    fn checked_in_example_configuration_is_valid() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("srh-config")
            .join("tokens.example.json");
        Config::from_path(path).expect("example configuration should remain valid");
    }
}
