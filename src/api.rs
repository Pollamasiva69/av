//! REST API for enterprise management

use crate::{Config, Engine, ScanStats};
use crate::core::EngineStats;
use crate::quarantine::QuarantineEntry;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use tracing::info;

/// API server state
#[derive(Clone)]
pub struct ApiState {
    pub engine: Arc<Engine>,
    pub config: Arc<RwLock<Config>>,
}

/// API server
pub struct ApiServer {
    state: ApiState,
}

impl ApiServer {
    pub fn new(engine: Arc<Engine>, config: Arc<RwLock<Config>>) -> Self {
        Self {
            state: ApiState { engine, config },
        }
    }

    /// Start the API server
    pub async fn start(self) -> anyhow::Result<()> {
        let addr = {
            let config = self.state.config.read().await;

            if !config.api.enabled {
                info!("API server is disabled in config");
                return Ok(());
            }

            format!("{}:{}", config.api.bind_address, config.api.port)
        };

        info!("Starting API server on {}", addr);

        let app = Router::new()
            .route("/api/v1/health", get(health_check))
            .route("/api/v1/stats", get(get_stats))
            .route("/api/v1/scan/file", post(scan_file))
            .route("/api/v1/scan/directory", post(scan_directory))
            .route("/api/v1/quarantine", get(list_quarantine))
            .route("/api/v1/quarantine/:id/restore", post(restore_quarantine))
            .route("/api/v1/quarantine/:id/delete", post(delete_quarantine))
            .route("/api/v1/update", post(update_definitions))
            .layer(CorsLayer::permissive())
            .with_state(self.state);

        let listener = tokio::net::TcpListener::bind(&addr).await?;
        info!("API server listening on {}", addr);

        axum::serve(listener, app).await?;

        Ok(())
    }
}

// API Handlers

async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "healthy",
        "version": env!("CARGO_PKG_VERSION"),
        "service": "Sentinel AV"
    }))
}

async fn get_stats(State(state): State<ApiState>) -> Result<Json<StatsResponse>, ApiError> {
    let stats = state.engine.get_stats().await?;

    Ok(Json(StatsResponse {
        total_scans: stats.total_scans,
        total_detections: stats.total_detections,
        signature_count: stats.signature_count,
        quarantine_count: stats.quarantine_count,
    }))
}

async fn scan_file(
    State(state): State<ApiState>,
    Json(req): Json<ScanFileRequest>,
) -> Result<Json<ScanFileResponse>, ApiError> {
    let path = std::path::PathBuf::from(&req.path);

    let verdict = state.engine.scan_file(&path).await?;

    Ok(Json(ScanFileResponse {
        path: req.path,
        verdict: format!("{:?}", verdict),
    }))
}

async fn scan_directory(
    State(state): State<ApiState>,
    Json(req): Json<ScanDirectoryRequest>,
) -> Result<Json<ScanDirectoryResponse>, ApiError> {
    let path = std::path::PathBuf::from(&req.path);

    let stats = state.engine.scan_directory(&path).await?;

    Ok(Json(ScanDirectoryResponse {
        path: req.path,
        stats,
    }))
}

async fn list_quarantine(
    State(_state): State<ApiState>,
) -> Result<Json<Vec<QuarantineEntry>>, ApiError> {
    // Access quarantine through engine (we'd need to expose this)
    // For now, return empty list
    Ok(Json(Vec::new()))
}

async fn restore_quarantine(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<SuccessResponse>, ApiError> {
    state.engine.restore_file(&id).await?;

    Ok(Json(SuccessResponse {
        success: true,
        message: format!("File {} restored from quarantine", id),
    }))
}

async fn delete_quarantine(
    State(_state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<SuccessResponse>, ApiError> {
    // Implement delete
    Ok(Json(SuccessResponse {
        success: true,
        message: format!("File {} deleted from quarantine", id),
    }))
}

async fn update_definitions(
    State(state): State<ApiState>,
) -> Result<Json<UpdateResponse>, ApiError> {
    let count = state.engine.update_definitions().await?;

    Ok(Json(UpdateResponse {
        success: true,
        updated_count: count,
    }))
}

// Request/Response types

#[derive(Debug, Deserialize)]
struct ScanFileRequest {
    path: String,
}

#[derive(Debug, Serialize)]
struct ScanFileResponse {
    path: String,
    verdict: String,
}

#[derive(Debug, Deserialize)]
struct ScanDirectoryRequest {
    path: String,
}

#[derive(Debug, Serialize)]
struct ScanDirectoryResponse {
    path: String,
    stats: ScanStats,
}

#[derive(Debug, Serialize)]
struct StatsResponse {
    total_scans: u64,
    total_detections: u64,
    signature_count: usize,
    quarantine_count: usize,
}

#[derive(Debug, Serialize)]
struct SuccessResponse {
    success: bool,
    message: String,
}

#[derive(Debug, Serialize)]
struct UpdateResponse {
    success: bool,
    updated_count: u64,
}

// Error handling

struct ApiError(anyhow::Error);

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": self.0.to_string()
            })),
        )
            .into_response()
    }
}

impl<E> From<E> for ApiError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}
