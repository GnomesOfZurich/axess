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
use uuid::Uuid;
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
        user_id: Uuid,
        id: Id,
    ) -> Result<Option<Record>, ValkeyStoreError> {
        let key = format!("session:{user_id}:{id}");
        if let Some(value) = self
            .client
            .get::<Option<Vec<u8>>, Key>(Key::from(key.as_bytes()))
            .await?
        {
            let decrypted_value = Self::decrypt_session_data(&value, &self.encryption_key);
            let record: Record = rmp_serde::from_slice(&decrypted_value)?;
            // info!("Session retrieved for ID: {}", id);
            Ok(Some(record))
        } else {
            // info!("No session found for ID: {}", id);
            Ok(None)
        }
    }

    pub async fn delete_session(&self, user_id: Uuid, id: Id) -> Result<i32, ValkeyStoreError> {
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
    pub fn encrypt_session_data(data: &[u8], key: &AesKey<Aes256Gcm>) -> Vec<u8> {
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits

        let mut encrypted_data = cipher.encrypt(&nonce, data).expect("encryption failure!");
        encrypted_data.extend_from_slice(&nonce);

        encrypted_data
    }

    // Decrypt session data
    pub fn decrypt_session_data(data: &[u8], key: &AesKey<Aes256Gcm>) -> Vec<u8> {
        let cipher = Aes256Gcm::new(key);
        let (ciphertext, nonce) = data.split_at(data.len() - 12);
        let nonce = Nonce::from_slice(nonce);

        cipher
            .decrypt(nonce, ciphertext)
            .expect("decryption failure!")
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
            let decrypted_data = Self::decrypt_session_data(&data, &self.encryption_key);
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

/// Initialize a Valkey cluster client, taking a vector of node adresses as inparameter (addresses expressed as "host:port" &str).
#[allow(dead_code)]
pub async fn init_valkey_cluster_client(nodes: Vec<&str>) -> Result<Client, ValkeyStoreError> {
    info!(
        "Creating Valkey cluster configuration with nodes: {:?}",
        nodes
    );
    // Split the vector of addresses into a vector of Server structs
    let servers: Vec<Server> = nodes
        .into_iter()
        .map(|addr| {
            let parts: Vec<&str> = addr.split(':').collect();
            Server::new(parts[0].to_string(), parts[1].parse().unwrap())
        })
        .collect();

    // Create the Config client configuration
    let config = Config {
        server: ServerConfig::Clustered {
            hosts: servers,
            policy: ClusterDiscoveryPolicy::ConfigEndpoint,
        },
        version: RespVersion::RESP3,
        // tls: Some(TlsConfig {
        //   connector: create_rustls_config(),
        //   hostnames: TlsHostMapping::DefaultHost,
        // }),
        // username: Some(read_redis_username()),
        // password: Some(read_redis_password()),
        ..Default::default()
    };

    // Initialize the Valkey cluster client
    info!("Initializing Valkey cluster client...");
    let client = Client::new(config, None, None, None::<ReconnectPolicy>);

    // Connect to the cluster asynchronously
    client.connect();
    client
        .wait_for_connect()
        .await
        .map_err(|e| {
            error!("Failed to connect to Valkey cluster: {:?}", e);
            ValkeyStoreError::Valkey(e)
        })?;

    info!("Valkey cluster client connected successfully");
    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;
    // use uuid::Uuid;

    #[tokio::test]
    #[ignore]
    async fn test_valkey_store_session_management() {
        // Initialize a Valkey cluster client
        println!("TEST 01: Initialize Valkey cluster client...");
        let cluster_addresses = vec!["0.0.0.0:6379", "0.0.0.0:6380", "0.0.0.0:6381"];
        let client = match init_valkey_cluster_client(cluster_addresses).await {
            Ok(client) => client,
            Err(e) => {
                eprintln!("Failed to connect to Valkey cluster: {:?}", e);
                return;
            }
        };

        let encryption_key = Aes256Gcm::generate_key(OsRng);
        let store = ValkeyStore::new(client, encryption_key);

        let session_id = Id::default();
        let mut data = std::collections::HashMap::new();
        data.insert(
            "test".to_string(),
            serde_json::Value::String("session_data".to_string()),
        );
        let record = Record {
            id: session_id,
            data,
            expiry_date: (time::OffsetDateTime::now_utc() + time::Duration::hours(24)),
        };

        // Test create session record
        store.create(&mut record.clone()).await.unwrap();

        // Test load session
        println!("TEST 10: Test load session...");
        let loaded_record = store.load(&session_id).await.unwrap();
        println!("TEST 11: Loaded record --> {:?}", loaded_record);
        assert!(loaded_record.is_some());
        println!("TEST 12: ...");
        assert_eq!(
            loaded_record.unwrap().data.get("test").unwrap(),
            &serde_json::Value::String("session_data".to_string())
        );

        // Test save session
        println!("TEST 20: Test save session...");
        let mut updated_data = std::collections::HashMap::new();
        updated_data.insert(
            "test".to_string(),
            serde_json::Value::String("updated_data".to_string()),
        );
        println!("TEST 21: Initial data --> {:?}", updated_data);
        let updated_record = Record {
            id: session_id,
            data: updated_data,
            expiry_date: (time::OffsetDateTime::now_utc() + time::Duration::hours(24)),
        };
        store.save(&updated_record).await.unwrap();
        let loaded_record = store.load(&session_id).await.unwrap();
        println!("TEST 22: Loaded stored updated record: {:?}", loaded_record);
        assert!(loaded_record.is_some());
        assert_eq!(
            loaded_record.unwrap().data.get("test").unwrap(),
            &serde_json::Value::String("updated_data".to_string())
        );

        // Test delete session
        println!("TEST 30: Test delete session...");
        store.delete(&session_id).await.unwrap();
        let loaded_record = store.load(&session_id).await.unwrap();
        println!("TEST 31: Loading of deleted record --> {:?}", loaded_record);
        assert!(loaded_record.is_none());
    }
}
