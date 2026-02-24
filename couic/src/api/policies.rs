use axum::{
    Extension, Json, Router,
    extract::State,
    http::StatusCode,
    middleware,
    response::IntoResponse,
    routing::{delete, get, post},
};
use tracing::{error, info};

use crate::extractors::ValidatedPath;
use crate::{
    api::{
        AppState,
        middleware::auth_middleware,
        rbac::{Resource, Scope, Verb},
    },
    error::CompositeError,
    extractors::ValidatedJson,
};
use common::{Action, Client, ErrorCode, PeerJob, Policy, PolicyPath, RawEntry};

/// List all entries based on policy
async fn list_entries(
    State(state): State<AppState>,
    ValidatedPath(policy): ValidatedPath<Policy>,
) -> impl IntoResponse {
    match state.firewall_service.list_entries(policy) {
        Ok(entries) => (StatusCode::OK, Json(entries)).into_response(),
        Err(ce) => ce.into_response(),
    }
}

// Create a new entry based on policy
async fn create_entry(
    State(state): State<AppState>,
    ValidatedPath(policy): ValidatedPath<Policy>,
    Extension(client): Extension<Client>,
    ValidatedJson(raw_entry): ValidatedJson<RawEntry>,
) -> impl IntoResponse {
    let (entry, metadata) = raw_entry.into_entry_and_metadata();
    match state
        .firewall_service
        .add_entry(policy, &entry, metadata, true)
    {
        Ok(()) => {
            info!(
                client.name = %client.name,
                client.group = %client.group,
                policy = %policy,
                cidr = %entry.cidr,
                tag = entry.tag.as_deref().unwrap_or(""),
                expiration = %entry.expiration,
                "entry created"
            );
            (StatusCode::CREATED, Json(entry)).into_response()
        }
        Err(ce) => {
            error!("failed to create entry: {ce}");
            ce.into_response()
        }
    }
}

/// Get a specific entry based on policy
async fn get_entry(
    State(state): State<AppState>,
    ValidatedPath(policy_path): ValidatedPath<PolicyPath>,
) -> impl IntoResponse {
    match state
        .firewall_service
        .get_entry(policy_path.policy, policy_path.cidr)
    {
        Ok(entry) => (StatusCode::OK, Json(entry)).into_response(),
        Err(ce) => ce.into_response(),
    }
}

/// Delete an entry based on policy
async fn delete_entry(
    State(state): State<AppState>,
    ValidatedPath(policy_path): ValidatedPath<PolicyPath>,
    Extension(client): Extension<Client>,
) -> impl IntoResponse {
    match state
        .firewall_service
        .get_entry(policy_path.policy, policy_path.cidr)
    {
        Ok(entry) => {
            if entry.in_set() {
                error!(
                    "failed to delete entry: policy={}, cidr={} is in a set",
                    policy_path.policy, policy_path.cidr
                );
                return CompositeError::new(
                    ErrorCode::Econflict,
                    "Entry defined in a set cannot be removed",
                )
                .into_response();
            }

            match state
                .firewall_service
                .remove_entry(policy_path.policy, policy_path.cidr, true)
            {
                Ok(()) => {
                    info!(
                        client.name = %client.name,
                        client.group = %client.group,
                        policy = %policy_path.policy,
                        cidr = %policy_path.cidr,
                        "entry deleted"
                    );
                    StatusCode::NO_CONTENT.into_response()
                }
                Err(ce) => {
                    error!(
                        client.name = %client.name,
                        client.group = %client.group,
                        policy = %policy_path.policy,
                        cidr = %policy_path.cidr,
                        error = %ce,
                        "failed to delete entry"
                    );
                    ce.into_response()
                }
            }
        }
        Err(ce) => ce.into_response(),
    }
}

async fn peer_entries(
    State(state): State<AppState>,
    ValidatedPath(policy): ValidatedPath<Policy>,
    Extension(client): Extension<Client>,
    Json(jobs): Json<Vec<PeerJob>>,
) -> impl IntoResponse {
    for job in &jobs {
        match job.action {
            Action::Add => {
                if let Err(ce) = state.firewall_service.add_entry(
                    policy,
                    &job.entry.clone().into_entry(),
                    None,
                    false,
                ) {
                    return ce.into_response();
                }
            }
            Action::Remove => {
                if let Err(ce) = state
                    .firewall_service
                    .remove_entry(policy, job.entry.cidr, false)
                {
                    return ce.into_response();
                }
            }
        }
    }
    info!(
        client.name = %client.name,
        client.group = %client.group,
        policy = %policy,
        jobs_count = jobs.len(),
        "peer entries synchronized"
    );
    (StatusCode::CREATED, Json(jobs)).into_response()
}

/// Create router for endpoints based on policy
pub(super) fn router(state: AppState) -> Router<AppState> {
    Router::new()
        .route(
            "/v1/{policy}",
            get(list_entries)
                .route_layer(middleware::from_fn_with_state(
                    state.clone(),
                    auth_middleware,
                ))
                .route_layer(Extension(Scope::with(Resource::Policy, Verb::List))),
        )
        .route(
            "/v1/{policy}",
            post(create_entry)
                .route_layer(middleware::from_fn_with_state(
                    state.clone(),
                    auth_middleware,
                ))
                .route_layer(Extension(Scope::with(Resource::Policy, Verb::Create))),
        )
        .route(
            "/v1/{policy}/{ip}/{prefix}",
            get(get_entry)
                .route_layer(middleware::from_fn_with_state(
                    state.clone(),
                    auth_middleware,
                ))
                .route_layer(Extension(Scope::with(Resource::Policy, Verb::Get))),
        )
        .route(
            "/v1/{policy}/{ip}/{prefix}",
            delete(delete_entry)
                .route_layer(middleware::from_fn_with_state(
                    state.clone(),
                    auth_middleware,
                ))
                .route_layer(Extension(Scope::with(Resource::Policy, Verb::Delete))),
        )
        .route(
            "/v1/{policy}/peer",
            post(peer_entries)
                .route_layer(middleware::from_fn_with_state(state, auth_middleware))
                .route_layer(Extension(Scope::with(Resource::Policy, Verb::Peer))),
        )
}
