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

    pub async fn delete_session(
        &self,
        user_id: impl std::fmt::Display,
        id: Id,
    ) -> Result<i32, ValkeyStoreError> {
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
    pub fn encrypt_session_data(
        data: &[u8],
        key: &AesKey<Aes256Gcm>,
    ) -> Result<Vec<u8>, ValkeyStoreError> {
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits

        let encrypted_data = cipher.encrypt(&nonce, data).map_err(|e| {
            error!("Session data encryption failed: {}", e);
            ValkeyStoreError::Valkey(Error::new(
                fred::error::ErrorKind::Unknown,
                format!("Encryption failure: {}", e),
            ))
        })?;

        let mut result = encrypted_data;
        result.extend_from_slice(&nonce);
        Ok(result)
    }

    // Decrypt session data
    pub fn decrypt_session_data(
        data: &[u8],
        key: &AesKey<Aes256Gcm>,
    ) -> Result<Vec<u8>, ValkeyStoreError> {
        if data.len() < 12 {
            error!(
                "Invalid encrypted session data: too short (length: {})",
                data.len()
            );
            return Err(ValkeyStoreError::Valkey(Error::new(
                fred::error::ErrorKind::Unknown,
                "Invalid encrypted session data: insufficient length",
            )));
        }

        let cipher = Aes256Gcm::new(key);
        let (ciphertext, nonce) = data.split_at(data.len() - 12);
        let nonce = Nonce::clone_from_slice(nonce);

        cipher.decrypt(&nonce, ciphertext).map_err(|e| {
            error!("Session data decryption failed: {}", e);
            ValkeyStoreError::Valkey(Error::new(
                fred::error::ErrorKind::Unknown,
                format!("Decryption failure: {}", e),
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

/// Initialize a Valkey cluster client, taking a vector of node addresses, an optional password, and an optional reconnect policy.
#[allow(dead_code)]
pub async fn init_valkey_cluster_client(
    nodes: Vec<&str>,
    password: Option<&str>,
    reconnect_policy: Option<ReconnectPolicy>,
) -> Result<Client, ValkeyStoreError> {
    info!(
        "Creating Valkey cluster configuration with nodes: {:?}",
        nodes
    );

    // Validate input nodes
    if nodes.is_empty() {
        error!("Cannot initialize Valkey cluster with empty node list");
        return Err(ValkeyStoreError::Valkey(Error::new(
            fred::error::ErrorKind::Config,
            "Empty node list provided for cluster initialization",
        )));
    }

    // Split the vector of addresses into a vector of Server structs with proper error handling
    let mut servers = Vec::new();
    for addr in &nodes {
        let parts: Vec<&str> = addr.split(':').collect();
        if parts.len() != 2 {
            error!(
                "Invalid node address format: '{}'. Expected 'host:port'",
                addr
            );
            return Err(ValkeyStoreError::Valkey(Error::new(
                fred::error::ErrorKind::Config,
                format!("Invalid node address format: '{}'", addr),
            )));
        }

        let host = parts[0].to_string();
        let port = parts[1].parse::<u16>().map_err(|e| {
            error!(
                "Invalid port number '{}' in address '{}': {}",
                parts[1], addr, e
            );
            ValkeyStoreError::Valkey(Error::new(
                fred::error::ErrorKind::Config,
                format!("Invalid port number in address '{}': {}", addr, e),
            ))
        })?;

        servers.push(Server::new(host, port));
    }

    // Create the Config client configuration
    let mut config = Config {
        server: ServerConfig::Clustered {
            hosts: servers,
            policy: ClusterDiscoveryPolicy::ConfigEndpoint,
        },
        version: RespVersion::RESP3,
        ..Default::default()
    };

    // Set password if provided
    if let Some(pass) = password {
        config.password = Some(pass.to_string());
    }

    // Use provided reconnect policy if Some, otherwise use sensible exponential backoff defaults
    let reconnect = match reconnect_policy {
        Some(policy) => policy,
        None => ReconnectPolicy::new_exponential(5, 1000, 30000, 2),
    };

    // Initialize the Valkey cluster client
    info!("Initializing Valkey cluster client...");
    let client = Client::new(config, None, None, Some(reconnect));

    // Connect to the cluster asynchronously with proper error handling
    info!("Connecting to Valkey cluster...");
    client.connect();

    // Wait for connection with detailed error context
    let connection_result = client.wait_for_connect().await;

    match connection_result {
        Ok(()) => {
            info!("Successfully connected to Valkey cluster");
            Ok(client)
        }
        Err(connection_error) => {
            error!("❌ CRITICAL: Valkey cluster connection failed");
            error!("🔧 Attempted nodes: {:?}", nodes);
            error!("🔧 Error details: {:?}", connection_error);
            error!("💡 This error typically means:");

            // Safe error kind matching without potential panics
            let error_kind = connection_error.kind();
            match error_kind {
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

            Err(ValkeyStoreError::Valkey(connection_error))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    // use tracing::warn;

    #[tokio::test]
    #[ignore]
    async fn test_valkey_store_session_management_comprehensive()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let cluster_addresses = vec!["127.0.0.1:6379", "127.0.0.1:6380", "127.0.0.1:6381"];
        let password = None;
        let reconnect_policy = None;

        info!("Initializing Valkey cluster client for fintech session storage");
        let client =
            match init_valkey_cluster_client(cluster_addresses, password, reconnect_policy).await {
                Ok(c) => c,
                Err(e) => {
                    error!("Failed to connect to Valkey cluster: {:?}", e);
                    return Err(Box::<dyn std::error::Error + Send + Sync>::from(e));
                }
            };

        let encryption_key = Aes256Gcm::generate_key(OsRng);
        let store = ValkeyStore::new(client, encryption_key);

        // create session, propagate errors instead of panicking
        let session_id = Id::default();
        let mut record = Record {
            id: session_id,
            data: HashMap::new(),
            expiry_date: OffsetDateTime::now_utc() + time::Duration::hours(1),
        };

        store
            .create(&mut record)
            .await
            .map_err(|e| Box::<dyn std::error::Error + Send + Sync>::from(e))?;

        // load and assert using `expect` only for invariants if desired
        let loaded_record = store
            .load(&session_id)
            .await
            .map_err(|e| Box::<dyn std::error::Error + Send + Sync>::from(e))?
            .ok_or_else(|| "expected session to exist")?;

        assert_eq!(loaded_record.id, session_id);

        // ... rest of test, using ? and map_err as above ...
        Ok(())
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

        assert_ne!(
            encrypted, original_data,
            "Encrypted data should differ from original"
        );
        assert!(
            encrypted.len() > original_data.len(),
            "Encrypted data should be longer due to nonce"
        );

        // Test decryption
        let decrypted = ValkeyStore::decrypt_session_data(&encrypted, &encryption_key)
            .expect("Decryption should succeed");

        assert_eq!(
            decrypted, original_data,
            "Decrypted data should match original"
        );
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
        assert!(
            result.is_err(),
            "Decryption should fail with corrupted data"
        );
    }

    /// Integration test for user-specific session management
    #[tokio::test]
    #[ignore] // Requires running Valkey cluster
    async fn test_user_specific_session_operations() {
        let cluster_addresses = vec!["127.0.0.1:6379"];
        let password = None;
        let reconnect_policy = None;
        let client = init_valkey_cluster_client(cluster_addresses, password, reconnect_policy)
            .await
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
        store
            .create(&mut record.clone())
            .await
            .expect("Failed to create user session");

        let loaded = store
            .get_session(user_id, session_id)
            .await
            .expect("Failed to load user session");

        assert!(loaded.is_some(), "User session should be retrievable");

        let deleted_count = store
            .delete_session(user_id, session_id)
            .await
            .expect("Failed to delete user session");

        assert_eq!(deleted_count, 1, "Should delete exactly one session");

        // Verify deletion
        let after_delete = store
            .get_session(user_id, session_id)
            .await
            .expect("Failed to check deleted user session");

        assert!(
            after_delete.is_none(),
            "User session should not exist after deletion"
        );
    }
}
