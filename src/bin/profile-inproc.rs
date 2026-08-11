//! In-process profiling harness: the real Hyper + Axum + domain stack driven over an
//! in-memory duplex transport instead of TCP.
//!
//! The socket-based capture (`scripts/profile.sh`) spends roughly a third of its cycles in
//! the kernel: loopback TCP for the client hop, loopback TCP for the Redis hop, and the
//! syscalls around both. That cost is real in production but it is not *ours*, and it
//! crowds out the code we can actually change. This harness removes it entirely:
//!
//! * transport is `tokio::io::duplex`, so there are no sockets and no softirq work;
//! * the executor is a constant reply, so there is no Redis hop and no `fred` I/O.
//!
//! Everything else is the production path — the same `http::router`, the same admission
//! layer stack, the same `StaticAuth` digest lookup, ACL check, rate limiter, JSON parse,
//! and `redis_value_to_json` conversion, and the same Hyper h1 codec.
//!
//! The load generator runs on a *separate* runtime whose worker threads are named
//! `srh-loadgen`, so its cost is attributable and subtractable:
//!
//! ```text
//! cargo build --profile profiling --features testsupport --bin profile-inproc
//! perf record -F 997 -g --call-graph fp -o target/profiling-inproc/perf.data -- \
//!   ./target/profiling/profile-inproc --duration 30 --connections 32
//! perf report -i target/profiling-inproc/perf.data --comms srh-server --no-children --stdio
//! ```
//!
//! This is a microscope for our own CPU and allocation cost, not a replacement for the
//! end-to-end capture: it deliberately removes backpressure, real Redis latency, and the
//! socket read patterns that drive Hyper's buffer growth. Throughput printed here is not
//! comparable to `scripts/profile.sh`; cycles-per-request within a single mode are.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::extract::ConnectInfo;
use axum::extract::Extension;
use bytes::Bytes;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use srh_rs::adapters::static_auth::StaticAuth;
use srh_rs::adapters::system_clock::SystemClock;
use srh_rs::config::Config;
use srh_rs::domain::rate_limit::RateLimiter;
use srh_rs::domain::resp::{AcquireError, ExecError, PoolReadiness, RespValue};
use srh_rs::ports::{
    Authenticator, Clock, CommandExecutor, ExecutorHandle, ExecutorProvider, RedisCommand,
};
use srh_rs::{AppState, AppStateInner, http};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Replies to every command with one fixed value.
///
/// A scripted [`srh_rs::testsupport::FakeExecutor`] cannot drive a sustained load run: its
/// reply queue drains and it records every call into an unbounded `Vec`. This allocates
/// nothing per call so the profile shows the proxy's own allocation behavior, not the
/// harness's.
struct ConstExecutor {
    reply: RespValue,
}

#[async_trait]
impl CommandExecutor for ConstExecutor {
    async fn execute(&self, _command: RedisCommand) -> Result<RespValue, ExecError> {
        Ok(self.reply.clone())
    }

    async fn pipeline(&self, commands: Vec<RedisCommand>) -> Vec<Result<RespValue, ExecError>> {
        commands.iter().map(|_| Ok(self.reply.clone())).collect()
    }

    async fn transaction(
        &self,
        commands: Vec<RedisCommand>,
    ) -> Result<Vec<Result<RespValue, ExecError>>, ExecError> {
        Ok(commands.iter().map(|_| Ok(self.reply.clone())).collect())
    }
}

/// Hands out the constant executor with a zero-sized lease.
///
/// Pool admission (semaphore permits, waiter queue, circuit breaker) lives in
/// `PoolManager` and is deliberately excluded here — it is inseparable from the Redis
/// connections it guards. Compare against the socket capture when that path matters.
struct ConstProvider {
    executor: Arc<dyn CommandExecutor>,
}

#[async_trait]
impl ExecutorProvider for ConstProvider {
    async fn acquire(&self, _pool: &str) -> Result<ExecutorHandle, AcquireError> {
        Ok(ExecutorHandle::new(
            Arc::clone(&self.executor),
            Box::new(()),
        ))
    }

    async fn readiness(&self) -> Vec<PoolReadiness> {
        Vec::new()
    }
}

struct Args {
    duration: Duration,
    connections: usize,
    config_path: String,
    token: String,
    body: String,
    path: String,
    reply: String,
    server_threads: usize,
    loadgen_threads: usize,
}

impl Args {
    fn parse() -> Self {
        let mut args = Self {
            duration: Duration::from_secs(30),
            connections: 32,
            config_path: "profiling/config.json".to_owned(),
            token: "phase9-load-token".to_owned(),
            body: r#"["GET","load:key"]"#.to_owned(),
            path: "/".to_owned(),
            reply: "phase9-value".to_owned(),
            server_threads: 0,
            loadgen_threads: 0,
        };
        let mut raw = std::env::args().skip(1);
        while let Some(flag) = raw.next() {
            let mut value = || {
                raw.next()
                    .unwrap_or_else(|| panic!("flag {flag} requires a value"))
            };
            match flag.as_str() {
                "--duration" => {
                    args.duration = Duration::from_secs_f64(
                        value().parse().expect("--duration must be seconds"),
                    );
                }
                "--connections" => {
                    args.connections = value().parse().expect("--connections must be a count");
                }
                "--config" => args.config_path = value(),
                "--token" => args.token = value(),
                "--body" => args.body = value(),
                "--path" => args.path = value(),
                "--reply" => args.reply = value(),
                "--server-threads" => {
                    args.server_threads =
                        value().parse().expect("--server-threads must be a count");
                }
                "--loadgen-threads" => {
                    args.loadgen_threads =
                        value().parse().expect("--loadgen-threads must be a count");
                }
                "--help" | "-h" => {
                    println!(
                        "profile-inproc [--duration SECS] [--connections N] [--config PATH]\n\
                         [--token TOKEN] [--body JSON] [--path /|/pipeline|/multi-exec]\n\
                         [--reply STRING] [--server-threads N] [--loadgen-threads N]"
                    );
                    std::process::exit(0);
                }
                other => panic!("unknown flag {other}"),
            }
        }
        assert!(args.connections > 0, "--connections must be positive");
        args
    }
}

fn build_state(args: &Args) -> AppState {
    let config = Arc::new(
        Config::from_path(&args.config_path)
            .unwrap_or_else(|error| panic!("failed to load {}: {error}", args.config_path)),
    );
    config
        .validate()
        .unwrap_or_else(|error| panic!("profiling config is invalid: {error}"));
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let authenticator: Arc<dyn Authenticator> =
        Arc::new(StaticAuth::new(config.auth.static_tokens.clone()));
    let rate_limiter = Arc::new(RateLimiter::new(
        config.server.rate_limit.per_token_commands_per_sec,
        Arc::clone(&clock),
    ));
    let executor: Arc<dyn CommandExecutor> = Arc::new(ConstExecutor {
        reply: RespValue::Bulk(Bytes::from(args.reply.clone())),
    });
    let provider: Arc<dyn ExecutorProvider> = Arc::new(ConstProvider { executor });
    AppState::new(AppStateInner {
        provider,
        authenticator,
        clock,
        rate_limiter,
        cfg: config,
    })
}

fn request_bytes(args: &Args) -> Bytes {
    Bytes::from(format!(
        "POST {} HTTP/1.1\r\n\
         Host: profile.invalid\r\n\
         Authorization: Bearer {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: keep-alive\r\n\r\n{}",
        args.path,
        args.token,
        args.body.len(),
        args.body
    ))
}

/// Drives one keep-alive connection until `stop`, counting completed responses.
///
/// The client is deliberately hand-rolled rather than a Hyper client: a second Hyper
/// stack on the same process would be indistinguishable from the server's in a flame
/// graph even with the thread-name split, because the symbols are identical.
async fn drive(
    mut client: tokio::io::DuplexStream,
    request: Bytes,
    stop: Arc<AtomicBool>,
    completed: Arc<AtomicU64>,
    failed: Arc<AtomicU64>,
) {
    let mut buffer = Vec::with_capacity(4096);
    while !stop.load(Ordering::Relaxed) {
        if client.write_all(&request).await.is_err() {
            failed.fetch_add(1, Ordering::Relaxed);
            return;
        }
        buffer.clear();
        let mut head_end = None;
        let mut content_length = 0usize;
        loop {
            if head_end.is_none()
                && let Some(position) = find_head_end(&buffer)
            {
                content_length = parse_content_length(&buffer[..position]);
                head_end = Some(position);
            }
            if let Some(position) = head_end
                && buffer.len() >= position + content_length
            {
                break;
            }
            let mut chunk = [0u8; 2048];
            match client.read(&mut chunk).await {
                Ok(0) | Err(_) => {
                    failed.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                Ok(read) => buffer.extend_from_slice(&chunk[..read]),
            }
        }
        completed.fetch_add(1, Ordering::Relaxed);
    }
}

fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|start| start + 4)
}

fn parse_content_length(head: &[u8]) -> usize {
    let head = str::from_utf8(head).unwrap_or_default();
    head.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0)
}

fn main() {
    let args = Args::parse();
    let state = build_state(&args);
    let app = http::router(state);
    let request = request_bytes(&args);

    let available = std::thread::available_parallelism().map_or(4, std::num::NonZero::get);
    let server_threads = if args.server_threads > 0 {
        args.server_threads
    } else {
        available.div_ceil(2)
    };
    let loadgen_threads = if args.loadgen_threads > 0 {
        args.loadgen_threads
    } else {
        available.div_ceil(2)
    };

    let server_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(server_threads)
        .thread_name("srh-server")
        .enable_all()
        .build()
        .expect("server runtime must build");
    let loadgen_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(loadgen_threads)
        .thread_name("srh-loadgen")
        .enable_all()
        .build()
        .expect("loadgen runtime must build");

    let stop = Arc::new(AtomicBool::new(false));
    let completed = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicU64::new(0));
    let mut drivers = Vec::with_capacity(args.connections);

    for index in 0..args.connections {
        let (client, server) = tokio::io::duplex(64 * 1024);
        // Mirrors the production accept loop: the same per-connection `ConnectInfo`
        // extension layer, so `/ready` and the layer stack match byte for byte.
        let peer = SocketAddr::from((
            Ipv4Addr::LOCALHOST,
            u16::try_from(40000 + index % 20000).unwrap_or(40000),
        ));
        let service = TowerToHyperService::new(app.clone().layer(Extension(ConnectInfo(peer))));
        server_runtime.spawn(async move {
            let mut builder = http1::Builder::new();
            builder
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(3));
            let _ = builder
                .serve_connection(TokioIo::new(server), service)
                .await;
        });
        drivers.push(loadgen_runtime.spawn(drive(
            client,
            request.clone(),
            Arc::clone(&stop),
            Arc::clone(&completed),
            Arc::clone(&failed),
        )));
    }

    // Let the connections reach steady state before the measured window opens, so
    // per-connection setup is not amortized into the reported rate.
    std::thread::sleep(Duration::from_millis(500));
    let baseline = completed.load(Ordering::Relaxed);
    let started = Instant::now();
    std::thread::sleep(args.duration);
    let measured = completed.load(Ordering::Relaxed) - baseline;
    let elapsed = started.elapsed();
    stop.store(true, Ordering::Relaxed);

    loadgen_runtime.shutdown_timeout(Duration::from_secs(5));
    server_runtime.shutdown_timeout(Duration::from_secs(5));

    let failures = failed.load(Ordering::Relaxed);
    println!(
        "requests={measured} elapsed={:.3}s throughput={:.0} req/s connections={} failures={failures}",
        elapsed.as_secs_f64(),
        f64::from(u32::try_from(measured).unwrap_or(u32::MAX)) / elapsed.as_secs_f64(),
        args.connections,
    );
    assert_eq!(failures, 0, "in-process harness must not drop connections");
}
