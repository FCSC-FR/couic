use std::collections::{HashMap, HashSet, hash_map};
use std::fmt;
use std::fs;
use std::path::Path;

use tracing::info;
use uuid::Uuid;

use crate::config::Config;
use crate::error::CompositeError;
use crate::security::{SEC_FILE_PERM, SecurityService};
use common::{Client, ClientFile, ClientName, ErrorCode, Group};

const DEFAULT_USER: &str = "couicctl";

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}:{:?}", self.resource, self.verb)
    }
}

#[derive(Debug, Eq, PartialEq, Hash, Clone, Copy)]
pub enum Resource {
    Policy,
    Sets,
    Stats,
    Clients,
    Any,
}

#[derive(Debug, Eq, PartialEq, Hash, Clone, Copy)]
pub enum Verb {
    Get,
    List,
    Delete,
    Create,
    Update,
    Peer,
    Any,
}

#[derive(Debug, Eq, PartialEq, Hash, Clone, Copy)]
pub struct Scope {
    resource: Resource,
    verb: Verb,
}

impl Scope {
    pub fn with(resource: Resource, verb: Verb) -> Self {
        Self { resource, verb }
    }

    fn matches(self, other: Scope) -> bool {
        (self.resource == Resource::Any || self.resource == other.resource)
            && (self.verb == Verb::Any || self.verb == other.verb)
    }
}

pub struct RBACService {
    clients: HashMap<Uuid, Client>,
    roles: HashMap<Group, HashSet<Scope>>,
    config: Config,
}

impl RBACService {
    pub fn new(config: Config) -> Result<Self, CompositeError> {
        let mut service = Self {
            clients: HashMap::new(),
            roles: Self::default_roles(),
            config,
        };
        service.load_clients()?;
        Ok(service)
    }

    fn default_roles() -> HashMap<Group, HashSet<Scope>> {
        HashMap::from([
            (
                Group::Admin,
                HashSet::from([Scope::with(Resource::Any, Verb::Any)]),
            ),
            (
                Group::ClientRo,
                HashSet::from([
                    Scope::with(Resource::Policy, Verb::Get),
                    Scope::with(Resource::Policy, Verb::List),
                    Scope::with(Resource::Sets, Verb::Get),
                    Scope::with(Resource::Sets, Verb::List),
                ]),
            ),
            (
                Group::ClientRw,
                HashSet::from([
                    Scope::with(Resource::Policy, Verb::Any),
                    Scope::with(Resource::Sets, Verb::Any),
                ]),
            ),
            (
                Group::Monitoring,
                HashSet::from([
                    Scope::with(Resource::Stats, Verb::List),
                    Scope::with(Resource::Stats, Verb::Get),
                ]),
            ),
            (
                Group::Peering,
                HashSet::from([Scope::with(Resource::Policy, Verb::Peer)]),
            ),
        ])
    }

    pub fn get_client_by_name(&self, name: &ClientName) -> Result<Client, CompositeError> {
        if let Some(client) = self
            .clients
            .values()
            .find(|c| c.name.as_str() == name.as_str())
        {
            Ok(client.clone())
        } else {
            Err(CompositeError::new(
                ErrorCode::Enotfound,
                &format!("Client not found: {name}"),
            ))
        }
    }

    pub fn list_clients(&self) -> Vec<Client> {
        self.clients.values().cloned().collect()
    }

    pub fn add_client(&mut self, client: &Client) -> Result<Client, CompositeError> {
        if self
            .clients
            .values()
            .any(|c| c.name.as_str() == client.name.as_str())
        {
            return Err(CompositeError::new(
                ErrorCode::Einvalid,
                &format!("Client name already exists: {}", client.name),
            ));
        }

        // Save the client to a file
        self.create_client_file(client)?;

        // Insert and return the new client
        let entry = self.clients.entry(client.token).or_insert(client.clone());
        Ok(entry.clone())
    }

    pub fn delete_client_by_name(&mut self, name: &ClientName) -> Result<(), CompositeError> {
        if let Some(token) = self
            .clients
            .values()
            .find(|c| c.name.as_str() == name.as_str())
            .map(|c| c.token)
        {
            if let Some(client) = self.clients.get(&token)
                && client.name.as_str() == DEFAULT_USER
            {
                return Err(CompositeError::new(
                    ErrorCode::Einvalid,
                    "Cannot delete default client",
                ));
            }
            // Remove and return the client
            if let Some(client) = self.clients.remove(&token) {
                // Remove the client file
                self.remove_client_file(&client)?;
                Ok(())
            } else {
                Err(CompositeError::new(
                    ErrorCode::Enotfound,
                    &format!("Client not found: {name}"),
                ))
            }
        } else {
            Err(CompositeError::new(
                ErrorCode::Enotfound,
                &format!("Client not found: {name}"),
            ))
        }
    }

    pub fn check_authorization(&self, token: Uuid, scope: Scope) -> Option<Client> {
        let client = self.clients.get(&token)?;
        let permissions = self.roles.get(&client.group)?;

        // Check if any permission matches
        permissions
            .iter()
            .any(|perm| perm.matches(scope))
            .then_some(client.clone())
    }

    /// Reloads clients from configuration directories
    fn load_clients(&mut self) -> Result<(), CompositeError> {
        let clients_dir = Path::new(&self.config.working_dir)
            .join("rbac")
            .join("clients");

        let mut found_default_client = false;

        for entry in fs::read_dir(&clients_dir).map_err(|e| {
            CompositeError::new(
                ErrorCode::Einternal,
                &format!("Failed to read clients directory: {e}"),
            )
        })? {
            let entry = entry.map_err(|e| {
                CompositeError::new(
                    ErrorCode::Einternal,
                    &format!("Failed to access directory entry: {e}"),
                )
            })?;

            let path = entry.path();
            if !Self::is_client_file(&path) {
                continue;
            }

            let client = self.load_client_from_file(&path)?;
            if client.name.as_str() == DEFAULT_USER {
                found_default_client = true;
            }

            match self.clients.entry(client.token) {
                hash_map::Entry::Vacant(e) => {
                    e.insert(client);
                }
                hash_map::Entry::Occupied(_) => {
                    return Err(CompositeError::new(
                        ErrorCode::Einvalid,
                        &format!("Duplicate client token found: {}", path.display()),
                    ));
                }
            }
        }

        if !found_default_client {
            let default_client = self.create_default_client()?;
            self.clients.insert(default_client.token, default_client);
        }

        Ok(())
    }

    /// Checks if the path is a client TOML file
    fn is_client_file(path: &Path) -> bool {
        path.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("toml")
    }

    /// Loads a single client from a TOML file
    fn load_client_from_file(&self, path: &Path) -> Result<Client, CompositeError> {
        SecurityService::check_owner_group_perms(
            path,
            &self.config.user,
            &self.config.group,
            SEC_FILE_PERM,
        )
        .map_err(|e| {
            CompositeError::new(
                ErrorCode::Einvalid,
                &format!(
                    "RBAC client file {} has wrong permissions: {e}",
                    path.display()
                ),
            )
        })?;

        let content = fs::read_to_string(path).map_err(|e| {
            CompositeError::new(
                ErrorCode::Einternal,
                &format!("Failed to read file {}: {e}", path.display()),
            )
        })?;

        let file_data: ClientFile = toml::from_str(&content).map_err(|e| {
            CompositeError::new(
                ErrorCode::Einvalid,
                &format!("Failed to parse TOML in file {}: {e}", path.display()),
            )
        })?;

        let file_name = path
            .file_stem()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                CompositeError::new(
                    ErrorCode::Einvalid,
                    &format!("Invalid file name: {}", path.display()),
                )
            })?;

        let name = ClientName::try_from(file_name).map_err(|e| {
            CompositeError::new(
                ErrorCode::Einvalid,
                &format!("Invalid client name {file_name}: {e}"),
            )
        })?;

        Ok(Client {
            name,
            token: file_data.token,
            group: file_data.group,
        })
    }

    /// Creates the default client if missing
    fn create_default_client(&self) -> Result<Client, CompositeError> {
        let token = Uuid::new_v4();
        let name = ClientName::try_from(DEFAULT_USER).map_err(|e| {
            CompositeError::new(
                ErrorCode::Einternal,
                &format!("Invalid default client name: {e}"),
            )
        })?;

        let client = Client {
            name,
            group: Group::Admin,
            token,
        };

        self.create_client_file(&client)?;
        Ok(client)
    }

    fn create_client_file(&self, client: &Client) -> Result<(), CompositeError> {
        let clients_dir = Path::new(&self.config.working_dir)
            .join("rbac")
            .join("clients");
        let client_path = clients_dir.join(format!("{}.toml", client.name));
        let file_data = ClientFile {
            token: client.token,
            group: client.group.clone(),
        };
        let toml_content = toml::to_string(&file_data).map_err(|e| {
            CompositeError::new(
                ErrorCode::Einternal,
                &format!("Failed to serialize client {}: {e}", client.name),
            )
        })?;

        // Write to a temporary file
        let tmp_path = client_path.with_extension("toml.tmp");
        fs::write(&tmp_path, &toml_content).map_err(|e| {
            CompositeError::new(
                ErrorCode::Einternal,
                &format!(
                    "Failed to write temp client file {}: {e}",
                    tmp_path.display()
                ),
            )
        })?;

        // Set owner/group/perms before renaming
        SecurityService::set_owner_group_perms(
            &tmp_path,
            &self.config.user,
            &self.config.group,
            SEC_FILE_PERM,
        )
        .map_err(|e| {
            CompositeError::new(
                ErrorCode::Einternal,
                &format!(
                    "Failed to set owner/group/perms for {}: {e}",
                    tmp_path.display()
                ),
            )
        })?;

        // Move to final location
        fs::rename(&tmp_path, &client_path).map_err(|e| {
            CompositeError::new(
                ErrorCode::Einternal,
                &format!(
                    "Failed to move temp client file {} to {}: {e}",
                    tmp_path.display(),
                    client_path.display()
                ),
            )
        })?;

        info!("Client file created: {}", client_path.display());
        Ok(())
    }

    // remove client file
    fn remove_client_file(&self, client: &Client) -> Result<(), CompositeError> {
        let clients_dir = Path::new(&self.config.working_dir)
            .join("rbac")
            .join("clients");
        let client_path = clients_dir.join(format!("{}.toml", client.name));
        if client_path.exists() {
            fs::remove_file(&client_path).map_err(|e| {
                CompositeError::new(
                    ErrorCode::Einternal,
                    &format!(
                        "Failed to remove client file {}: {e}",
                        client_path.display()
                    ),
                )
            })?;
            info!("Client file removed: {}", client_path.display());
            Ok(())
        } else {
            Err(CompositeError::new(
                ErrorCode::Enotfound,
                &format!("Client file not found: {}", client_path.display()),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use tempfile::TempDir;

    fn create_test_config() -> (Config, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        // Get current user and group
        let current_user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
        let current_group = current_user.clone(); // Often the same as username on Linux
        let config = Config {
            working_dir: temp_dir.path().to_string_lossy().to_string(),
            user: current_user,
            group: current_group,
            ..Default::default()
        };

        // Create rbac/clients directory
        std::fs::create_dir_all(temp_dir.path().join("rbac").join("clients")).unwrap();

        (config, temp_dir)
    }

    #[test]
    fn test_scope_creation_and_display() {
        let scope = Scope::with(Resource::Policy, Verb::Get);
        assert_eq!(scope.to_string(), "Policy:Get");

        let any_scope = Scope::with(Resource::Any, Verb::Any);
        assert_eq!(any_scope.to_string(), "Any:Any");
    }

    #[test]
    fn test_rbac_service_new() {
        let (config, _temp_dir) = create_test_config();
        let service = RBACService::new(config).unwrap();

        // Should have default client
        assert_eq!(service.clients.len(), 1);
        let default_client = service.clients.values().next().unwrap();
        assert_eq!(default_client.name.as_str(), DEFAULT_USER);
        assert_eq!(default_client.group, Group::Admin);
        assert!(!default_client.token.is_nil());
        // Default client file should be couicctl.toml
        let client_file = Path::new(&service.config.working_dir)
            .join("rbac")
            .join("clients")
            .join(format!("{}.toml", DEFAULT_USER));
        assert!(client_file.exists());

        // Should have all roles configured
        assert_eq!(service.roles.len(), 5);
        assert!(service.roles.contains_key(&Group::Admin));
        assert!(service.roles.contains_key(&Group::ClientRo));
        assert!(service.roles.contains_key(&Group::ClientRw));
        assert!(service.roles.contains_key(&Group::Monitoring));
        assert!(service.roles.contains_key(&Group::Peering));
    }

    fn make_client(name: &str, group: Group) -> Client {
        Client {
            name: ClientName::try_from(name).unwrap(),
            group,
            token: Uuid::new_v4(),
        }
    }

    #[test]
    fn test_add_client() {
        let (config, _temp_dir) = create_test_config();
        let mut service = RBACService::new(config).unwrap();

        let request = make_client("test-client", Group::ClientRo);

        let client = service.add_client(&request).unwrap();
        assert_eq!(client.name.as_str(), "test-client");
        assert_eq!(client.group, Group::ClientRo);
        assert_eq!(service.clients.len(), 2); // default + new
    }

    #[test]
    fn test_add_duplicate_client() {
        let (config, _temp_dir) = create_test_config();
        let mut service = RBACService::new(config).unwrap();

        let request = make_client("test-client", Group::ClientRo);

        service.add_client(&request).unwrap();
        let result = service.add_client(&request);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("already exists"));
    }

    #[test]
    fn test_get_client_by_name() {
        let (config, _temp_dir) = create_test_config();
        let mut service = RBACService::new(config).unwrap();

        let request = make_client("test-client", Group::ClientRo);
        service.add_client(&request).unwrap();

        let client = service
            .get_client_by_name(&ClientName::try_from("test-client").unwrap())
            .unwrap();
        assert_eq!(client.name.as_str(), "test-client");

        let not_found = service.get_client_by_name(&ClientName::try_from("nonexistent").unwrap());
        assert!(not_found.is_err());
    }

    #[test]
    fn test_delete_client() {
        let (config, _temp_dir) = create_test_config();
        let mut service = RBACService::new(config).unwrap();

        let request = make_client("test-client", Group::ClientRo);
        service.add_client(&request).unwrap();

        assert_eq!(service.clients.len(), 2);
        service
            .delete_client_by_name(&ClientName::try_from("test-client").unwrap())
            .unwrap();
        assert_eq!(service.clients.len(), 1);

        let not_found =
            service.delete_client_by_name(&ClientName::try_from("test-client").unwrap());
        assert!(not_found.is_err());
    }

    #[test]
    fn test_delete_default_client_forbidden() {
        let (config, _temp_dir) = create_test_config();
        let mut service = RBACService::new(config).unwrap();

        let result = service.delete_client_by_name(&ClientName::try_from(DEFAULT_USER).unwrap());
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .message
                .contains("Cannot delete default client")
        );
    }

    #[test]
    fn test_authorize_admin_client() {
        let (config, _temp_dir) = create_test_config();
        let service = RBACService::new(config).unwrap();

        let admin_client = service
            .get_client_by_name(&ClientName::try_from(DEFAULT_USER).unwrap())
            .unwrap();
        let scope = Scope::with(Resource::Policy, Verb::Delete);

        let result = service.check_authorization(admin_client.token, scope);
        assert!(result.is_some());
        assert_eq!(result.unwrap().name.as_str(), DEFAULT_USER);
    }

    #[test]
    fn test_check_authorization_ro_permissions() {
        let (config, _temp_dir) = create_test_config();
        let mut service = RBACService::new(config).unwrap();

        let request = make_client("ro-client", Group::ClientRo);

        let client_token = {
            let client = service.add_client(&request).unwrap();
            client.token
        };

        // Should allow read operations
        let read_scope = Scope::with(Resource::Policy, Verb::Get);
        assert!(
            service
                .check_authorization(client_token, read_scope)
                .is_some()
        );

        let list_scope = Scope::with(Resource::Policy, Verb::List);
        assert!(
            service
                .check_authorization(client_token, list_scope)
                .is_some()
        );

        // Should deny write operations
        let delete_scope = Scope::with(Resource::Policy, Verb::Delete);
        assert!(
            service
                .check_authorization(client_token, delete_scope)
                .is_none()
        );
    }

    #[test]
    fn test_check_authorization_rw_permissions() {
        let (config, _temp_dir) = create_test_config();
        let mut service = RBACService::new(config).unwrap();

        let request = make_client("rw-client", Group::ClientRw);
        let client_token = {
            let client = service.add_client(&request).unwrap();
            client.token
        };

        // Should allow all operations on Drop and Ignore resources
        let delete_scope = Scope::with(Resource::Policy, Verb::Delete);
        assert!(
            service
                .check_authorization(client_token, delete_scope)
                .is_some()
        );

        let create_scope = Scope::with(Resource::Policy, Verb::Create);
        assert!(
            service
                .check_authorization(client_token, create_scope)
                .is_some()
        );

        // Should deny operations on Stats resource
        let stats_scope = Scope::with(Resource::Stats, Verb::Get);
        assert!(
            service
                .check_authorization(client_token, stats_scope)
                .is_none()
        );
    }

    #[test]
    fn test_authorize_monitoring_client() {
        let (config, _temp_dir) = create_test_config();
        let mut service = RBACService::new(config).unwrap();

        let request = make_client("monitor-client", Group::Monitoring);
        let client_token = {
            let client = service.add_client(&request).unwrap();
            client.token
        };

        // Should allow stats access
        let stats_scope = Scope::with(Resource::Stats, Verb::List);
        assert!(
            service
                .check_authorization(client_token, stats_scope)
                .is_some()
        );

        // Should deny other operations
        let policy_scope = Scope::with(Resource::Policy, Verb::List);
        assert!(
            service
                .check_authorization(client_token, policy_scope)
                .is_none()
        );
    }

    #[test]
    fn test_authorize_peering_client() {
        let (config, _temp_dir) = create_test_config();
        let mut service = RBACService::new(config).unwrap();

        let request = make_client("peer-client", Group::Peering);
        let client_token = {
            let client = service.add_client(&request).unwrap();
            client.token
        };

        // Should allow peer operations on Drop
        let peer_scope = Scope::with(Resource::Policy, Verb::Peer);
        assert!(
            service
                .check_authorization(client_token, peer_scope)
                .is_some()
        );

        // Should deny other operations
        let get_scope = Scope::with(Resource::Policy, Verb::Get);
        assert!(
            service
                .check_authorization(client_token, get_scope)
                .is_none()
        );
    }

    #[test]
    fn test_authorize_invalid_token() {
        let (config, _temp_dir) = create_test_config();
        let service = RBACService::new(config).unwrap();

        let invalid_token = Uuid::new_v4();
        let scope = Scope::with(Resource::Policy, Verb::Get);

        assert!(service.check_authorization(invalid_token, scope).is_none());
    }

    #[test]
    fn test_list_clients() {
        let (config, _temp_dir) = create_test_config();
        let mut service = RBACService::new(config).unwrap();

        let request1 = make_client("client1", Group::ClientRo);
        let request2 = make_client("client2", Group::ClientRw);

        service.add_client(&request1).unwrap();
        service.add_client(&request2).unwrap();

        let clients = service.list_clients();
        assert_eq!(clients.len(), 3); // default + 2 new

        let names: Vec<&str> = clients.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&DEFAULT_USER));
        assert!(names.contains(&"client1"));
        assert!(names.contains(&"client2"));
    }

    #[test]
    fn test_client_serialization() {
        let client = Client {
            name: ClientName::try_from("test-client").unwrap(),
            token: Uuid::new_v4(),
            group: Group::ClientRo,
        };

        let serialized = toml::to_string(&client).unwrap();
        let deserialized: Client = toml::from_str(&serialized).unwrap();

        assert_eq!(client.name, deserialized.name);
        assert_eq!(client.token, deserialized.token);
        assert_eq!(client.group, deserialized.group);
    }

    #[test]
    fn test_scope_matches_exact() {
        let scope = Scope::with(Resource::Policy, Verb::Get);
        assert!(scope.matches(Scope::with(Resource::Policy, Verb::Get)));
        assert!(!scope.matches(Scope::with(Resource::Policy, Verb::Delete)));
        assert!(!scope.matches(Scope::with(Resource::Stats, Verb::Get)));
    }

    #[test]
    fn test_scope_matches_any_resource() {
        let any_resource = Scope::with(Resource::Any, Verb::Get);
        assert!(any_resource.matches(Scope::with(Resource::Policy, Verb::Get)));
        assert!(any_resource.matches(Scope::with(Resource::Stats, Verb::Get)));
        assert!(!any_resource.matches(Scope::with(Resource::Policy, Verb::Delete)));
    }

    #[test]
    fn test_scope_matches_any_verb() {
        let any_verb = Scope::with(Resource::Policy, Verb::Any);
        assert!(any_verb.matches(Scope::with(Resource::Policy, Verb::Get)));
        assert!(any_verb.matches(Scope::with(Resource::Policy, Verb::Delete)));
        assert!(!any_verb.matches(Scope::with(Resource::Stats, Verb::Get)));
    }

    #[test]
    fn test_scope_matches_any_any() {
        let any_any = Scope::with(Resource::Any, Verb::Any);
        assert!(any_any.matches(Scope::with(Resource::Policy, Verb::Get)));
        assert!(any_any.matches(Scope::with(Resource::Stats, Verb::Delete)));
        assert!(any_any.matches(Scope::with(Resource::Clients, Verb::Create)));
    }

    #[test]
    fn test_load_clients_with_existing_files() {
        let (config, temp_dir) = create_test_config();

        // Create a pre-existing client file
        let clients_dir = temp_dir.path().join("rbac").join("clients");
        let client_token = Uuid::new_v4();
        let client_content = format!(
            r#"token = "{}"
group = "clientro"
"#,
            client_token
        );
        let client_path = clients_dir.join("existing-client.toml");
        std::fs::write(&client_path, &client_content).unwrap();

        // Set correct permissions
        use crate::security::{SEC_FILE_PERM, SecurityService};
        SecurityService::set_owner_group_perms(
            &client_path,
            &config.user,
            &config.group,
            SEC_FILE_PERM,
        )
        .unwrap();

        // Create service - should load the existing client
        let service = RBACService::new(config).unwrap();

        // Should have 2 clients: default + existing
        assert_eq!(service.clients.len(), 2);

        // Verify the existing client was loaded
        let existing = service
            .get_client_by_name(&ClientName::try_from("existing-client").unwrap())
            .unwrap();
        assert_eq!(existing.token, client_token);
        assert_eq!(existing.group, Group::ClientRo);
    }

    #[test]
    fn test_load_clients_duplicate_token_error() {
        let (config, temp_dir) = create_test_config();

        let clients_dir = temp_dir.path().join("rbac").join("clients");
        let duplicate_token = Uuid::new_v4();

        // Create two client files with the same token
        for name in &["client1", "client2"] {
            let content = format!(
                r#"token = "{}"
group = "clientro"
"#,
                duplicate_token
            );
            let path = clients_dir.join(format!("{}.toml", name));
            std::fs::write(&path, &content).unwrap();

            use crate::security::{SEC_FILE_PERM, SecurityService};
            SecurityService::set_owner_group_perms(
                &path,
                &config.user,
                &config.group,
                SEC_FILE_PERM,
            )
            .unwrap();
        }

        // Should fail due to duplicate token
        let result = RBACService::new(config);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.message.contains("Duplicate client token"));
    }

    #[test]
    fn test_load_clients_with_default_client_file() {
        let (config, temp_dir) = create_test_config();

        // Create a default client file (couicctl.toml)
        let clients_dir = temp_dir.path().join("rbac").join("clients");
        let default_token = Uuid::new_v4();
        let client_content = format!(
            r#"token = "{}"
group = "admin"
"#,
            default_token
        );
        let client_path = clients_dir.join("couicctl.toml");
        std::fs::write(&client_path, &client_content).unwrap();

        use crate::security::{SEC_FILE_PERM, SecurityService};
        SecurityService::set_owner_group_perms(
            &client_path,
            &config.user,
            &config.group,
            SEC_FILE_PERM,
        )
        .unwrap();

        // Create service - should use the existing default client
        let service = RBACService::new(config).unwrap();

        // Should have only 1 client (the pre-existing default)
        assert_eq!(service.clients.len(), 1);

        // Verify the default client has the token from the file
        let default = service
            .get_client_by_name(&ClientName::try_from(DEFAULT_USER).unwrap())
            .unwrap();
        assert_eq!(default.token, default_token);
    }
}
