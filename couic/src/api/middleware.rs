use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use tracing::warn;
use uuid::Uuid;

use super::AppState;
use super::rbac::Scope;
use crate::error::CompositeError;
use common::ErrorCode;

/// Custom authentication middleware for Bearer Token
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, Response> {
    // Extract and validate Authorization header
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok());

    let Some(header_value) = auth_header else {
        warn!("Missing Authorization header");
        return Err(unauthorized_error());
    };

    // Parse Bearer token
    let token = header_value.strip_prefix("Bearer ").ok_or_else(|| {
        warn!("Invalid Authorization header format");
        unauthorized_error()
    })?;

    let uuid_token = Uuid::parse_str(token).map_err(|_| {
        warn!("Invalid UUID token format: {}", token);
        unauthorized_error()
    })?;

    // Get scope
    let Some(scope) = req.extensions().get::<Scope>() else {
        warn!("Missing scope extension on protected route");
        return Err(unauthorized_error());
    };

    let client = state
        .rbac_service
        .read()
        .await
        .check_authorization(uuid_token, *scope);

    if let Some(client) = client {
        // Store client for handlers logging
        req.extensions_mut().insert(client);

        Ok(next.run(req).await)
    } else {
        warn!("Unauthorized access attempt with token: {}", uuid_token);
        Err(unauthorized_error())
    }
}

fn unauthorized_error() -> Response {
    CompositeError::new(ErrorCode::Eunauthorized, "Unauthorized")
        .render_json()
        .into_response()
}
