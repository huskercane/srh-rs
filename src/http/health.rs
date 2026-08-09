use std::collections::BTreeMap;
use std::net::SocketAddr;

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::AppState;
use crate::domain::resp::PoolReadinessStatus;

pub async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

pub async fn ready(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
) -> Response {
    if !peer.ip().is_loopback() {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "Not found" }))).into_response();
    }
    let mut all_ready = true;
    let pools = state
        .provider
        .readiness()
        .await
        .into_iter()
        .map(|pool| {
            let value = match pool.status {
                PoolReadinessStatus::Ready => json!({ "status": "ready" }),
                PoolReadinessStatus::Unavailable(reason) => {
                    all_ready = false;
                    json!({ "status": "unavailable", "error": reason })
                }
            };
            (pool.pool, value)
        })
        .collect::<BTreeMap<_, _>>();
    let status = if all_ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(json!({
            "status": if all_ready { "ready" } else { "not_ready" },
            "pools": pools
        })),
    )
        .into_response()
}
