//! HTTP API (axum). M1.1: health endpoint only;
//! auth middleware and mesh endpoints arrive with M1.2/M2.
//! `serve` is wired into `main` when the `run` command grows a server (M2.3).
#![allow(dead_code)]

use axum::{routing::get, Json, Router};
use serde_json::json;
use std::net::SocketAddr;

async fn health() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

pub fn router() -> Router {
    Router::new().route("/api/health", get(health))
}

pub async fn serve(port: u16) -> anyhow::Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "listening");
    axum::serve(listener, router()).await?;
    Ok(())
}
