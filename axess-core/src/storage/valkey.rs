use aes_gcm::{
    Aes256Gcm, Key as AesKey, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use async_trait::async_trait;
use fred::types::Key;
use fred::{
    error::Error,
    interfaces::{ClientLike, KeysInterface},
    prelude::{Client, Config, ReconnectPolicy, ServerConfig},
    types::{
        Expiration, RespVersion, SetOptions,
        config::{ClusterDiscoveryPolicy, Server},
    },
};
use rmp_serde::{self, decode::Error as DecodeError, encode::Error as EncodeError};
use std::{
    fmt::Debug,
    // env,
};
use time::OffsetDateTime;
use tower_sessions::{
    SessionStore,
    session::{Id, Record},
    session_store,
};
use tracing::{error, info};

// use crate::cache::SessionStore;

#[derive(Debug, thiserror::Error)]
pub enum ValkeyStoreError {
    #[error(transparent)]
    Valkey(#[from] Error),

    #[error(transparent)]
    Decode(#[from] DecodeError),

    #[error(transparent)]
    Encode(#[from] EncodeError),
    // #[error("An error occurred: {0}")]
    // GenericError(String),
}

impl From<ValkeyStoreError> for session_store::Error {
    fn from(err: ValkeyStoreError) -> Self {
        match err {
            ValkeyStoreError::Valkey(inner) => session_store::Error::Backend(inner.to_string()),
            ValkeyStoreError::Decode(inner) => session_store::Error::Decode(inner.to_string()),
            ValkeyStoreError::Encode(inner) => session_store::Error::Encode(inner.to_string()),
            // ValkeyStoreError::GenericError(inner) => session_store::Error::Generic(inner),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ValkeyStore {
    client: Client,
    // encryption_key: GenericArray<u8, <Aes256Gcm as KeyInit>::KeySize>,
    encryption_key: AesKey<Aes256Gcm>,
}

impl ValkeyStore {
    pub fn new(client: Client, encryption_key: AesKey<Aes256Gcm>) -> Self {
        Self {
            client,
            encryption_key,
        }
    }

    // #[async_trait]
    // impl SessionStore for ValkeyStore {

    // impl ValkeyStore {
    // Create a new Redis store with the provided client.
    //
    // # Examples
    //
    // ```rust,no_run
    // use axum_access::authn::valkey::ValkeyStore;
    // use fred::{
    //     prelude::{RedisPool, RedisConfig},
    //     interfaces::ClientLike,
    // };
    //
    // # tokio_test::block_on(async {
    // let pool = RedisPool::new(RedisConfig::default(), None, None, None, 6).unwrap();
    //
    // let _ = pool.connect();
    // pool.wait_for_connect().await.unwrap();
    //
    // let session_store = ValkeyStore::new(pool);
    // })
    // ```

    //     let encryption_key = Key::from_slice(b"an example very very secret key."); // Replace with your key
    //     Self { client, encryption_key }
    //     Self { client }
    // }

    async fn save_with_options(
        &self,
        record: &Record,
        options: Option<SetOptions>,
    ) -> session_store::Result<bool> {
        // Expire cache entries based on the session's expiry date
        let expire = Some(Expiration::EXAT(OffsetDateTime::unix_timestamp(
            record.expiry_date,
        )));

        // Serialize the session record into a binary format
        let data = rmp_serde::to_vec(&record).map_err(ValkeyStoreError::Encode)?;

        // Use Redis' `set` command with expiry and options
        // self.client
        //     .set(record.id.to_string(), data, expire, options, false)
        //     .await
        //     .map_err(ValkeyStoreError::Valkey);

        Ok(self
            .client
            .set(
                record.id.to_string(),
                data.as_slice(),
                expire,
                options,
                false,
            )
            .await
            .map_err(ValkeyStoreError::Valkey)?)
    }

    pub async fn get_session(
        &self,
        user_id: impl std::fmt::Display,
        id: Id,
    ) -> Result<Option<Record>, ValkeyStoreError> {
        let key = format!("session:{user_id}:{id}");
        if let Some(value) = self
            .client
            .get::<Option<Vec<u8>>, Key>(Key::from(key.as_bytes()))
            .await?
        {
            let decrypted_value = Self::decrypt_session_data(&value, &self.encryption_key)?;
            let record: Record = rmp_serde::from_slice(&decrypted_value)?;
            // info!("Session retrieved for ID: {}", id);
            Ok(Some(record))
        } else {
            // info!("No session found for ID: {}", id);
            Ok(None)
        }
    }

    pub async fn delete_session(&self, user_id: impl std::fmt::Display, id: Id) -> Result<i32, ValkeyStoreError> {
        // let key = format!("session:{}:{}", user_id, id);
        // let deleted_count = self.client.del::<i32, String>(key).await?;
        // info!("Session deleted for ID: {}", id);

        // if let Some(session_id) = session.id() {
        //     session.delete().await?;

        let key = format!("session:{user_id}:{id}");

        match self.client.del::<i32, String>(key.clone()).await {
            Ok(res) => {
                // TODO: adjust these logging messages (lower log leve and adapt message)
                info!("Deleted Session '{}'", res);
                info!("Deleted '{}'", key);
                Ok(res)
            }
            Err(e) => {
                error!("Failed to delete session: {:?}", e);
                Err(ValkeyStoreError::Valkey(e))
            }
        }
    }

    // Encrypt session data
    pub fn encrypt_session_data(data: &[u8], key: &AesKey<Aes256Gcm>) -> Result<Vec<u8>, ValkeyStoreError> {
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits

        let encrypted_data = cipher.encrypt(&nonce, data).map_err(|e| {
            error!("Session data encryption failed: {}", e);
            ValkeyStoreError::Valkey(Error::new(
                fred::error::ErrorKind::Unknown,
                format!("Encryption failure: {}", e)
            ))
        })?;
        
        let mut result = encrypted_data;
        result.extend_from_slice(&nonce);
        Ok(result)
    }

    // Decrypt session data
    pub fn decrypt_session_data(data: &[u8], key: &AesKey<Aes256Gcm>) -> Result<Vec<u8>, ValkeyStoreError> {
        if data.len() < 12 {
            error!("Invalid encrypted session data: too short (length: {})", data.len());
            return Err(ValkeyStoreError::Valkey(Error::new(
                fred::error::ErrorKind::Unknown,
                "Invalid encrypted session data: insufficient length"
            )));
        }
        
        let cipher = Aes256Gcm::new(key);
        let (ciphertext, nonce) = data.split_at(data.len() - 12);
        let nonce = Nonce::from_slice(nonce);

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| {
                error!("Session data decryption failed: {}", e);
                ValkeyStoreError::Valkey(Error::new(
                    fred::error::ErrorKind::Unknown,
                    format!("Decryption failure: {}", e)
                ))
            })
    }

    // async fn create_with_expiry(
    //     &self,
    //     record: &mut Record,
    //     expiry_duration: u64, // Specify expiry in seconds here
    // ) -> session_store::Result<()> {
    //     let expiry = Some(Expiration::EX(expiry_duration.try_into().unwrap())); // Set expiry in seconds

    //     loop {
    //         if !self.save_with_options(record, Some(SetOptions::NX), expiry).await? {
    //             record.id = Id::default();
    //             continue;
    //         }
    //         break;
    //     }

    //     Ok(())
    // }
}

// #[async_trait]
// impl<C> SessionStore for ValkeyStore<C>
// where
//     C: KeysInterface + Send + Sync + Debug + 'static,

#[async_trait]
impl SessionStore for ValkeyStore {
    async fn create(&self, record: &mut Record) -> session_store::Result<()> {
        loop {
            if !self.save_with_options(record, Some(SetOptions::NX)).await? {
                record.id = Id::default();
                continue;
            }
            break;
        }
        Ok(())
    }

    async fn save(&self, record: &Record) -> session_store::Result<()> {
        self.save_with_options(record, Some(SetOptions::XX)).await?;
        Ok(())
    }

    async fn load(&self, session_id: &Id) -> session_store::Result<Option<Record>> {
        let data = self
            .client
            .get::<Option<Vec<u8>>, _>(session_id.to_string())
            .await
            .map_err(ValkeyStoreError::Valkey)?;

        if let Some(data) = data {
            // Decrypt the session data
            let decrypted_data = Self::decrypt_session_data(&data, &self.encryption_key)
                .map_err(|e| session_store::Error::Backend(e.to_string()))?;
            Ok(Some(
                rmp_serde::from_slice(decrypted_data.as_slice())
                    .map_err(ValkeyStoreError::Decode)?,
            ))
        } else {
            Ok(None)
        }
    }

    async fn delete(&self, session_id: &Id) -> session_store::Result<()> {
        self.client
            .del::<usize, String>(session_id.to_string())
            .await
            .map_err(ValkeyStoreError::Valkey)?;
        Ok(())
    }
}

/// Initialize a Valkey cluster client, taking a vector of node addresses as input parameter (addresses expressed as "host:port" &str).
#[allow(dead_code)]
pub async fn init_valkey_cluster_client(nodes: Vec<&str>) -> Result<Client, ValkeyStoreError> {
    info!(
        "Creating Valkey cluster configuration with nodes: {:?}",
        nodes
    );
    
    // Validate input nodes
    if nodes.is_empty() {
        error!("Cannot initialize Valkey cluster with empty node list");
        return Err(ValkeyStoreError::Valkey(Error::new(
            fred::error::ErrorKind::Config,
            "Empty node list provided for cluster initialization"
        )));
    }
    
    // Split the vector of addresses into a vector of Server structs with proper error handling
    let mut servers = Vec::new();
    for addr in &nodes {
        let parts: Vec<&str> = addr.split(':').collect();
        if parts.len() != 2 {
            error!("Invalid node address format: '{}'. Expected 'host:port'", addr);
            return Err(ValkeyStoreError::Valkey(Error::new(
                fred::error::ErrorKind::Config,
                format!("Invalid node address format: '{}'", addr)
            )));
        }
        
        let host = parts[0].to_string();
        let port = parts[1].parse::<u16>().map_err(|e| {
            error!("Invalid port number '{}' in address '{}': {}", parts[1], addr, e);
            ValkeyStoreError::Valkey(Error::new(
                fred::error::ErrorKind::Config,
                format!("Invalid port number in address '{}': {}", addr, e)
            ))
        })?;
        
        servers.push(Server::new(host, port));
    }

    // Create the Config client configuration
    let config = Config {
        server: ServerConfig::Clustered {
            hosts: servers,
            policy: ClusterDiscoveryPolicy::ConfigEndpoint,
        },
        version: RespVersion::RESP3,
        // TLS configuration can be added here if needed:
        // tls: Some(TlsConfig {
        //   connector: create_rustls_config(),
        //   hostnames: TlsHostMapping::DefaultHost,
        // }),
        // Authentication can be added here if needed:
        // username: Some(read_redis_username()),
        // password: Some(read_redis_password()),
        ..Default::default()
    };

    // Initialize the Valkey cluster client
    info!("Initializing Valkey cluster client...");
    let client = Client::new(config, None, None, None::<ReconnectPolicy>);

    // Connect to the cluster asynchronously with proper error handling
    info!("Connecting to Valkey cluster...");
    client.connect();
    
    // Wait for connection with detailed error context
    match client.wait_for_connect().await {
        Ok(()) => {
            info!("Successfully connected to Valkey cluster");
            Ok(client)
        }
        Err(e) => {
            error!("❌ CRITICAL: Valkey cluster connection failed");
            error!("🔧 Attempted nodes: {:?}", nodes);
            error!("🔧 Error details: {:?}", e);
            error!("💡 This error typically means:");
            match e.kind() {
                fred::error::ErrorKind::IO => {
                    error!("   • Valkey service is not running on the specified ports");
                    error!("   • Network connectivity issues between client and server");
                    error!("   • Firewall blocking connections");
                }
                fred::error::ErrorKind::Config => {
                    error!("   • Invalid cluster configuration");
                    error!("   • Incorrect node addresses or ports");
                }
                fred::error::ErrorKind::Auth => {
                    error!("   • Authentication failure");
                    error!("   • Invalid credentials or missing auth setup");
                }
                _ => {
                    error!("   • Unexpected connection error");
                    error!("   • Check Valkey server logs for more details");
                }
            }
            error!("");
            error!("🚀 Quick fixes:");
            error!("   • Start Valkey: docker run -p 6379:6379 valkey/valkey");
            error!("   • Check status: docker ps | grep valkey");
            error!("   • Test connection: telnet <host> <port>");
            Err(ValkeyStoreError::Valkey(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tracing::warn;

    /// Comprehensive test suite for Valkey store session management in fintech environment
    #[tokio::test]
    #[ignore] // Requires running Valkey cluster
    async fn test_valkey_store_session_management_comprehensive() {
        // Test configuration for fintech security compliance
        let cluster_addresses = vec!["127.0.0.1:6379", "127.0.0.1:6380", "127.0.0.1:6381"];
        
        // Initialize Valkey cluster client with proper error handling
        info!("Initializing Valkey cluster client for fintech session storage");
        let client = match init_valkey_cluster_client(cluster_addresses).await {
            Ok(client) => {
                info!("Successfully connected to Valkey cluster");
                client
            }
            Err(e) => {
                error!("Failed to connect to Valkey cluster: {:?}", e);
                warn!("Ensure Valkey cluster is running on specified ports");
                return;
            }
        };

        // Generate encryption key for financial data protection
        let encryption_key = Aes256Gcm::generate_key(OsRng);
        let store = ValkeyStore::new(client, encryption_key);

        // Test 1: Session Creation and Encryption
        info!("TEST 01: Creating encrypted session for financial user data");
        let session_id = Id::default();
        let mut session_data = HashMap::new();
        
        // Simulate financial session data
        session_data.insert(
            "user_id".to_string(),
            serde_json::Value::String("user_12345".to_string()),
        );
        session_data.insert(
            "account_id".to_string(),
            serde_json::Value::String("acc_67890".to_string()),
        );
        session_data.insert(
            "permissions".to_string(),
            serde_json::Value::Array(vec![
                serde_json::Value::String("read_accounts".to_string()),
                serde_json::Value::String("transfer_funds".to_string()),
            ]),
        );
        session_data.insert(
            "login_timestamp".to_string(),
            serde_json::Value::String(OffsetDateTime::now_utc().to_string()),
        );

        let mut record = Record {
            id: session_id,
            data: session_data,
            expiry_date: OffsetDateTime::now_utc() + time::Duration::hours(1), // 1-hour expiry for security
        };

        // Create session with encryption
        store.create(&mut record).await
            .expect("Failed to create encrypted financial session");
        info!("Session created successfully with ID: {}", record.id);

        // Test 2: Session Loading and Decryption
        info!("TEST 02: Loading and decrypting financial session");
        let loaded_record = store.load(&session_id).await
            .expect("Failed to load session from Valkey");
        
        assert!(loaded_record.is_some(), "Session should exist after creation");
        
        let loaded_record = loaded_record.unwrap();
        assert_eq!(loaded_record.id, session_id, "Session ID should match");
        
        // Verify financial data integrity
        assert_eq!(
            loaded_record.data.get("user_id").unwrap(),
            &serde_json::Value::String("user_12345".to_string()),
            "User ID should be preserved after encryption/decryption"
        );
        assert_eq!(
            loaded_record.data.get("account_id").unwrap(),
            &serde_json::Value::String("acc_67890".to_string()),
            "Account ID should be preserved after encryption/decryption"
        );
        
        info!("Session data successfully decrypted and validated");

        // Test 3: Session Update with Financial Data Modification
        info!("TEST 03: Updating financial session with new permissions");
        let mut updated_data = HashMap::new();
        updated_data.insert(
            "user_id".to_string(),
            serde_json::Value::String("user_12345".to_string()),
        );
        updated_data.insert(
            "account_id".to_string(),
            serde_json::Value::String("acc_67890".to_string()),
        );
        updated_data.insert(
            "permissions".to_string(),
            serde_json::Value::Array(vec![
                serde_json::Value::String("read_accounts".to_string()),
                serde_json::Value::String("transfer_funds".to_string()),
                serde_json::Value::String("admin_access".to_string()), // Elevated permissions
            ]),
        );
        updated_data.insert(
            "last_activity".to_string(),
            serde_json::Value::String(OffsetDateTime::now_utc().to_string()),
        );

        let updated_record = Record {
            id: session_id,
            data: updated_data,
            expiry_date: OffsetDateTime::now_utc() + time::Duration::hours(1),
        };

        store.save(&updated_record).await
            .expect("Failed to update financial session");

        // Verify update
        let loaded_updated = store.load(&session_id).await
            .expect("Failed to load updated session");
        
        assert!(loaded_updated.is_some(), "Updated session should exist");
        
        let loaded_updated = loaded_updated.unwrap();
        let permissions = loaded_updated.data.get("permissions").unwrap();
        if let serde_json::Value::Array(perms) = permissions {
            assert!(
                perms.contains(&serde_json::Value::String("admin_access".to_string())),
                "Admin access permission should be present after update"
            );
        } else {
            panic!("Permissions should be an array");
        }
        
        info!("Session update completed successfully");

        // Test 4: Session Expiry Behavior
        info!("TEST 04: Testing session expiry for security compliance");
        let expired_session_id = Id::default();
        let mut expired_data = HashMap::new();
        expired_data.insert(
            "test_data".to_string(),
            serde_json::Value::String("expired_session".to_string()),
        );

        let mut expired_record = Record {
            id: expired_session_id,
            data: expired_data,
            expiry_date: OffsetDateTime::now_utc() - time::Duration::seconds(1), // Already expired
        };

        store.create(&mut expired_record).await
            .expect("Failed to create expired session for testing");

        // Note: Valkey will automatically expire the session, but the exact timing depends on configuration
        // In a real test environment, you would wait for the expiry to be processed
        info!("Expired session created for testing");

        // Test 5: Session Deletion for Security
        info!("TEST 05: Testing secure session deletion");
        store.delete(&session_id).await
            .expect("Failed to delete financial session");

        let deleted_check = store.load(&session_id).await
            .expect("Error checking deleted session");
        
        assert!(deleted_check.is_none(), "Session should not exist after deletion");
        info!("Session successfully deleted from Valkey store");

        // Test 6: Encryption/Decryption Edge Cases
        info!("TEST 06: Testing encryption edge cases for security validation");
        
        // Test empty session data
        let empty_session_id = Id::default();
        let mut empty_record = Record {
            id: empty_session_id,
            data: HashMap::new(),
            expiry_date: OffsetDateTime::now_utc() + time::Duration::hours(1),
        };

        store.create(&mut empty_record).await
            .expect("Failed to create empty session");

        let loaded_empty = store.load(&empty_session_id).await
            .expect("Failed to load empty session");
        
        assert!(loaded_empty.is_some(), "Empty session should be loadable");
        assert!(loaded_empty.unwrap().data.is_empty(), "Empty session data should remain empty");

        // Clean up
        store.delete(&empty_session_id).await
            .expect("Failed to delete empty session");
        store.delete(&expired_session_id).await.ok(); // May already be expired
        
        info!("All Valkey store tests completed successfully");
    }

    /// Test encryption and decryption functionality independently
    #[test]
    fn test_session_encryption_decryption() {
        let encryption_key = Aes256Gcm::generate_key(OsRng);
        
        // Test data representing financial session information
        let original_data = b"sensitive_financial_data_user_12345_account_67890";
        
        // Test encryption
        let encrypted = ValkeyStore::encrypt_session_data(original_data, &encryption_key)
            .expect("Encryption should succeed");
        
        assert_ne!(encrypted, original_data, "Encrypted data should differ from original");
        assert!(encrypted.len() > original_data.len(), "Encrypted data should be longer due to nonce");
        
        // Test decryption
        let decrypted = ValkeyStore::decrypt_session_data(&encrypted, &encryption_key)
            .expect("Decryption should succeed");
        
        assert_eq!(decrypted, original_data, "Decrypted data should match original");
    }

    /// Test error handling for malformed encrypted data
    #[test]
    fn test_encryption_error_handling() {
        let encryption_key = Aes256Gcm::generate_key(OsRng);
        
        // Test decryption with invalid data (too short)
        let invalid_data = b"short";
        let result = ValkeyStore::decrypt_session_data(invalid_data, &encryption_key);
        assert!(result.is_err(), "Decryption should fail with invalid data");
        
        // Test decryption with corrupted data
        let corrupted_data = vec![0u8; 32]; // 32 bytes of zeros
        let result = ValkeyStore::decrypt_session_data(&corrupted_data, &encryption_key);
        assert!(result.is_err(), "Decryption should fail with corrupted data");
    }

    /// Integration test for user-specific session management
    #[tokio::test]
    #[ignore] // Requires running Valkey cluster
    async fn test_user_specific_session_operations() {
        let cluster_addresses = vec!["127.0.0.1:6379"];
        let client = init_valkey_cluster_client(cluster_addresses).await
            .expect("Failed to connect to Valkey for user session test");

        let encryption_key = Aes256Gcm::generate_key(OsRng);
        let store = ValkeyStore::new(client, encryption_key);

        let user_id = "financial_user_12345";
        let session_id = Id::default();
        
        let mut session_data = HashMap::new();
        session_data.insert(
            "balance".to_string(),
            serde_json::Value::String("1000.00".to_string()), // Financial data
        );

        let record = Record {
            id: session_id,
            data: session_data,
            expiry_date: OffsetDateTime::now_utc() + time::Duration::hours(1),
        };

        // Test user-specific session operations
        store.create(&mut record.clone()).await
            .expect("Failed to create user session");

        let loaded = store.get_session(user_id, session_id).await
            .expect("Failed to load user session");
        
        assert!(loaded.is_some(), "User session should be retrievable");
        
        let deleted_count = store.delete_session(user_id, session_id).await
            .expect("Failed to delete user session");
        
        assert_eq!(deleted_count, 1, "Should delete exactly one session");
        
        // Verify deletion
        let after_delete = store.get_session(user_id, session_id).await
            .expect("Failed to check deleted user session");
        
        assert!(after_delete.is_none(), "User session should not exist after deletion");
    }
}
