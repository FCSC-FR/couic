use reqwest::Url;
use reqwest::blocking::{Client as ReqwestClient, Response};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue, USER_AGENT};
use std::fmt::Write;
use std::path::Path;
use std::time::Duration;
use std::{fs, io};

use uuid::Uuid;

use common::{ClientFile, CompositeError, ErrorCode};

mod api;

pub use api::v1::{ClientsApi, PeerApi, PolicyApi, SetsApi, StatsApi};

#[derive(Debug, Clone, Copy, Default)]
pub enum ApiVersion {
    #[default]
    V1,
}

pub struct CouicClientBuilder {
    version: ApiVersion,
}

impl CouicClientBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            version: ApiVersion::default(),
        }
    }

    #[must_use]
    pub const fn version(mut self, version: ApiVersion) -> Self {
        self.version = version;
        self
    }

    pub fn build_local(self, config: LocalConfig) -> Result<CouicClient, CouicError> {
        CouicClient::new_local(config, self.version)
    }

    pub fn build_remote(self, config: &RemoteConfig) -> Result<CouicClient, CouicError> {
        CouicClient::new_remote(config, self.version)
    }
}

impl Default for CouicClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub const NAME: &str = "CouicClient";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const TIMEOUT: Duration = Duration::from_secs(5);
const USER_AGENT_VALUE: &str = concat!("CouicClient/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, thiserror::Error)]
pub enum CouicError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("{}", format_api_error(*.status, error))]
    ApiError { status: u16, error: CompositeError },
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("TOML error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("Invalid header value: {0}")]
    InvalidHeader(#[from] reqwest::header::InvalidHeaderValue),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),
}

fn format_api_error(status: u16, error: &CompositeError) -> String {
    let mut msg = format!(
        "API error:\n  Status: {}\n  Code: {}\n  Message: {}",
        status, error.code, error.message
    );
    if !error.errors.is_empty() {
        msg.push_str("\n  Details:");
        for (field, detail) in &error.errors {
            let _ = write!(msg, "\n    {field}: {detail}");
        }
    }
    msg
}

#[derive(Debug)]
pub struct CouicClient {
    base_url: Url,
    client: ReqwestClient,
    version: ApiVersion,
}

#[derive(Debug, Clone)]
pub enum LocalCredential {
    File(String),
    Token(Uuid),
}

pub struct LocalConfig {
    pub socket: String,
    pub credential: LocalCredential,
}

impl LocalConfig {
    #[must_use]
    pub fn from_file(socket: impl Into<String>, client_file: impl Into<String>) -> Self {
        Self {
            socket: socket.into(),
            credential: LocalCredential::File(client_file.into()),
        }
    }

    #[must_use]
    pub fn from_token(socket: impl Into<String>, token: Uuid) -> Self {
        Self {
            socket: socket.into(),
            credential: LocalCredential::Token(token),
        }
    }
}

pub struct RemoteConfig {
    pub token: Uuid,
    pub host: String,
    pub port: u16,
    pub tls: bool,
}

impl CouicClient {
    fn new_local(config: LocalConfig, version: ApiVersion) -> Result<Self, CouicError> {
        let socket = config.socket;
        if !Path::new(&socket).exists() {
            return Err(CouicError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Unix socket does not exist: {socket}"),
            )));
        }

        let token = match config.credential {
            LocalCredential::File(path) => Self::load_client_file(&path)?.token,
            LocalCredential::Token(token) => token,
        };
        let headers = Self::set_headers(&token.to_string())?;

        let client = ReqwestClient::builder()
            .default_headers(headers)
            .timeout(TIMEOUT)
            .unix_socket(socket)
            .build()?;

        let base_url = Url::parse("http://localhost")?;

        Ok(Self {
            base_url,
            client,
            version,
        })
    }

    fn new_remote(config: &RemoteConfig, version: ApiVersion) -> Result<Self, CouicError> {
        let scheme = if config.tls { "https" } else { "http" };
        let base_url = Url::parse(&format!("{scheme}://{}:{}", config.host, config.port))?;
        let headers = Self::set_headers(&config.token.to_string())?;

        let client = ReqwestClient::builder()
            .default_headers(headers)
            .timeout(TIMEOUT)
            .build()?;

        Ok(Self {
            base_url,
            client,
            version,
        })
    }

    #[must_use]
    pub const fn info(&self) -> &Url {
        &self.base_url
    }

    fn load_client_file<P: AsRef<Path>>(path: P) -> Result<ClientFile, CouicError> {
        let client_file = path.as_ref();
        if client_file.is_file()
            && client_file.extension().and_then(|ext| ext.to_str()) == Some("toml")
        {
            let content = fs::read_to_string(client_file)?;
            let client: ClientFile = toml::de::from_str(&content)?;
            return Ok(client);
        }
        Err(CouicError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid client file",
        )))
    }

    #[must_use]
    pub fn builder() -> CouicClientBuilder {
        CouicClientBuilder::new()
    }

    #[must_use]
    pub const fn stats(&self) -> api::v1::StatsApi<'_> {
        match self.version {
            ApiVersion::V1 => api::v1::StatsApi::new(self),
        }
    }

    #[must_use]
    pub const fn policy(&self) -> api::v1::PolicyApi<'_> {
        match self.version {
            ApiVersion::V1 => api::v1::PolicyApi::new(self),
        }
    }

    #[must_use]
    pub const fn clients(&self) -> api::v1::ClientsApi<'_> {
        match self.version {
            ApiVersion::V1 => api::v1::ClientsApi::new(self),
        }
    }

    #[must_use]
    pub const fn sets(&self) -> api::v1::SetsApi<'_> {
        match self.version {
            ApiVersion::V1 => api::v1::SetsApi::new(self),
        }
    }

    #[must_use]
    pub const fn peer(&self) -> api::v1::PeerApi<'_> {
        match self.version {
            ApiVersion::V1 => api::v1::PeerApi::new(self),
        }
    }

    fn url(&self, endpoint: &str) -> Result<Url, CouicError> {
        Ok(self.base_url.join(endpoint)?)
    }

    fn set_headers(token: &str) -> Result<HeaderMap, CouicError> {
        let mut headers = HeaderMap::with_capacity(4);
        headers.insert(USER_AGENT, HeaderValue::from_static(USER_AGENT_VALUE));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}"))?,
        );
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        Ok(headers)
    }

    fn parse_api_error(status: u16, text: &str) -> CouicError {
        let error = serde_json::from_str(text)
            .unwrap_or_else(|e| CompositeError::new(ErrorCode::Einternal, &e.to_string()));
        CouicError::ApiError { status, error }
    }

    fn handle_response<T: serde::de::DeserializeOwned>(
        response: Response,
    ) -> Result<T, CouicError> {
        let status = response.status();
        let text = response.text()?;

        if status.is_success() {
            Ok(serde_json::from_str(&text)?)
        } else {
            Err(Self::parse_api_error(status.as_u16(), &text))
        }
    }

    fn handle_empty_response(response: Response) -> Result<(), CouicError> {
        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            let text = response.text()?;
            Err(Self::parse_api_error(status.as_u16(), &text))
        }
    }

    pub(crate) fn get<T: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
    ) -> Result<T, CouicError> {
        let url = self.url(endpoint)?;
        let response = self.client.get(url).send()?;
        Self::handle_response(response)
    }

    pub(crate) fn post<T: serde::de::DeserializeOwned, B: serde::Serialize + ?Sized>(
        &self,
        endpoint: &str,
        body: Option<&B>,
    ) -> Result<T, CouicError> {
        let url = self.url(endpoint)?;
        let req = self.client.post(url);
        let req = if let Some(b) = body { req.json(b) } else { req };
        let response = req.send()?;
        Self::handle_response(response)
    }

    pub(crate) fn put<T: serde::de::DeserializeOwned, B: serde::Serialize>(
        &self,
        endpoint: &str,
        body: Option<&B>,
    ) -> Result<T, CouicError> {
        let url = self.url(endpoint)?;
        let req = self.client.put(url);
        let req = if let Some(b) = body { req.json(b) } else { req };
        let response = req.send()?;
        Self::handle_response(response)
    }

    pub(crate) fn post_empty(&self, endpoint: &str) -> Result<(), CouicError> {
        let url = self.url(endpoint)?;
        let response = self.client.post(url).send()?;
        Self::handle_empty_response(response)
    }

    pub(crate) fn delete(&self, endpoint: &str) -> Result<(), CouicError> {
        let url = self.url(endpoint)?;
        let response = self.client.delete(url).send()?;
        Self::handle_empty_response(response)
    }
}
