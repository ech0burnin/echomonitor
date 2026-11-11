//! Inter-node HTTP transport with HMAC-token auth.
//! Every request carries `X-Em-Token` (current 30s-period HMAC) and `X-Em-Node` (self id).
//! Middleware rejects anything whose token doesn't verify against the shared network secret.

// Whole module is wired into `main` in M2.2/M2.3 (gossip loop + serve).
// Until then items are exercised only by tests, hence the module-level allow.
#![allow(dead_code)]

use crate::crypto;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone)]
pub struct NodeState {
    pub network_secret: Arc<str>,
    pub self_id: u32,
    pub self_name: Arc<str>,
    pub revision: u64,
    pub content_hash: Arc<str>,
}

// ---------- auth middleware ----------

#[derive(Clone, Debug)]
pub struct VerifiedNode(pub String);

pub async fn auth_middleware(
    State(state): State<Arc<NodeState>>,
    mut req: Request,
    next: Next,
) -> Response {
    let token = req.headers().get("X-Em-Token").and_then(|v| v.to_str().ok());
    let node = req.headers().get("X-Em-Node").and_then(|v| v.to_str().ok());

    let (token, node) = match (token, node) {
        (Some(t), Some(n)) => (t, n.to_string()),
        _ => return (StatusCode::UNAUTHORIZED, "missing X-Em-Token / X-Em-Node").into_response(),
    };

    if !crypto::verify_token(&state.network_secret, token) {
        return (StatusCode::UNAUTHORIZED, "invalid or expired token").into_response();
    }

    req.extensions_mut().insert(VerifiedNode(node));
    next.run(req).await
}

// ---------- handlers ----------

async fn health() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

/// Inbound topology/state gossip. M2.1: accept and ack.
/// Full merge logic arrives with M2.2.
async fn gossip() -> Response {
    (StatusCode::OK, "gossip accepted").into_response()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GossipMessage {
    pub from: u32,
    pub revision: u64,
    pub nodes: Vec<crate::config::NodeEntry>,
    pub edges: Vec<crate::config::EdgeEntry>,
}

// ---------- client ----------

pub struct NodeClient {
    pub http: reqwest::Client,
    pub network_secret: Arc<str>,
    pub self_id: u32,
}

impl NodeClient {
    pub fn new(network_secret: Arc<str>, self_id: u32) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .expect("reqwest client"),
            network_secret,
            self_id,
        }
    }

    fn auth_headers(&self) -> reqwest::header::HeaderMap {
        let mut h = reqwest::header::HeaderMap::new();
        h.insert(
            "X-Em-Token",
            crypto::token_now(&self.network_secret)
                .parse()
                .expect("hex token is valid header value"),
        );
        h.insert(
            "X-Em-Node",
            self.self_id.to_string().parse().expect("numeric id"),
        );
        h
    }

    pub async fn health(&self, addr: &str) -> anyhow::Result<serde_json::Value> {
        let url = format!("http://{addr}/api/health");
        let resp = self.http.get(&url).headers(self.auth_headers()).send().await?;
        Ok(resp.json().await?)
    }

    pub async fn gossip(&self, addr: &str, msg: &GossipMessage) -> anyhow::Result<String> {
        let url = format!("http://{addr}/api/gossip");
        let resp = self
            .http
            .post(&url)
            .headers(self.auth_headers())
            .json(msg)
            .send()
            .await?;
        Ok(resp.text().await?)
    }
}

// ---------- router ----------

pub fn router(state: Arc<NodeState>) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route(
            "/api/gossip",
            post(gossip).route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            )),
        )
        .with_state(state)
}

pub async fn serve(state: Arc<NodeState>, port: u16) -> anyhow::Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router(state)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn gossip_requires_valid_token() {
        let state = Arc::new(NodeState {
            network_secret: "test-secret".into(),
            self_id: 1,
            self_name: "n1".into(),
            revision: 1,
            content_hash: "abc".into(),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });

        let client = reqwest::Client::new();

        // no headers -> 401
        let r = client
            .post(format!("http://127.0.0.1:{port}/api/gossip"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401);

        // valid token -> 200
        let nc = NodeClient::new("test-secret".into(), 1);
        let msg = GossipMessage {
            from: 1,
            revision: 1,
            nodes: vec![],
            edges: vec![],
        };
        let body = nc.gossip(&format!("127.0.0.1:{port}"), &msg).await.unwrap();
        assert_eq!(body, "gossip accepted");

        // wrong secret -> 401 (token from different secret)
        let bad = NodeClient::new("other-secret".into(), 1);
        let r = bad
            .http
            .post(format!("http://127.0.0.1:{port}/api/gossip"))
            .headers(bad.auth_headers())
            .json(&msg)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401);
    }
}
