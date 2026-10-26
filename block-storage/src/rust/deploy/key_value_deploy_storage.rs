// See block-storage/src/main/scala/coop/rchain/blockstorage/deploy/KeyValueDeployStorage.scala

use std::collections::HashSet;
use std::marker::PhantomData;
use std::sync::Arc;

use crypto::rust::signatures::signed::Signed;
use models::rust::casper::protocol::casper_message::DeployData;
use rspace_plus_plus::rspace::shared::key_value_store_manager::KeyValueStoreManager;
use shared::rust::store::key_value_store::{KeyValueStore, KvStoreError};
use shared::rust::store::key_value_typed_store::KeyValueTypedStore;
use shared::rust::store::key_value_typed_store_impl::KeyValueTypedStoreImpl;
use shared::rust::store::lmdb_key_value_store::LmdbKeyValueStore;
use shared::rust::ByteString;

use super::deploy_record_quarantine::DeployRecordQuarantine;

pub const DEPLOY_STORAGE_DB: &str = "deploy_storage";
pub const DEPLOY_STORAGE_QUARANTINE_DB: &str = "deploy_storage_quarantine";
pub const REJECTED_DEPLOY_BUFFER_DB: &str = "rejected_deploy_buffer";
pub const REJECTED_DEPLOY_BUFFER_QUARANTINE_DB: &str = "rejected_deploy_buffer_quarantine";

const DEPLOY_STORE_SIZE_METRIC: &str = "deploy.store.size";
const DEPLOY_STORE_READ_ALL_DECODED_METRIC: &str = "deploy-store.read-all.decoded";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeployMetadata {
    pub signature: Vec<u8>,
    pub valid_after_block_number: i64,
    pub timestamp: i64,
    pub expiration_timestamp: Option<i64>,
}

impl From<&Signed<DeployData>> for DeployMetadata {
    fn from(deploy: &Signed<DeployData>) -> Self {
        Self {
            signature: deploy.sig.to_vec(),
            valid_after_block_number: deploy.data.valid_after_block_number,
            timestamp: deploy.data.time_stamp,
            expiration_timestamp: deploy.data.expiration_timestamp,
        }
    }
}

pub fn store_revision(store: &Arc<dyn KeyValueStore>) -> Option<usize> {
    store
        .as_any()
        .downcast_ref::<LmdbKeyValueStore>()
        .map(|store| store.env.info().last_txn_id)
}

#[derive(Clone, Default)]
pub struct MetadataSnapshot {
    pub entries: imbl::HashMap<Vec<u8>, DeployMetadata>,
    pub generation: u64,
    pub parent_generation: Option<u64>,
    pub additions: Vec<DeployMetadata>,
    pub removals: Vec<Vec<u8>>,
}

#[derive(Default)]
pub(super) struct MetadataCache {
    pub revision: Option<usize>,
    pub initialized: bool,
    pub snapshot: MetadataSnapshot,
}

impl MetadataCache {
    pub fn update(
        &mut self,
        before: Option<usize>,
        after: Option<usize>,
        writes: usize,
        additions: Vec<DeployMetadata>,
        removals: Vec<Vec<u8>>,
    ) {
        let trusted = self.initialized
            && before.is_some()
            && before == self.revision
            && before.and_then(|id| id.checked_add(writes)) == after;
        self.revision = None;
        self.snapshot.parent_generation = None;
        self.snapshot.additions.clear();
        self.snapshot.removals.clear();
        if trusted {
            self.revision = after;
            if writes == 0 {
                return;
            }
            self.snapshot.parent_generation = Some(self.snapshot.generation);
            for deploy in &additions {
                self.snapshot
                    .entries
                    .insert(deploy.signature.clone(), deploy.clone());
            }
            for signature in &removals {
                self.snapshot.entries.remove(signature);
            }
            self.snapshot.additions = additions;
            self.snapshot.removals = removals;
        }
        self.snapshot.generation = self.snapshot.generation.wrapping_add(1);
    }
}

pub trait DeployStoreName {
    const NAME: &'static str;
    const QUARANTINE_NAME: &'static str;
    const SIZE_WARNING_THRESHOLD: Option<usize> = None;
}

#[derive(Clone)]
pub struct DeployStorageName;

impl DeployStoreName for DeployStorageName {
    const NAME: &'static str = DEPLOY_STORAGE_DB;
    const QUARANTINE_NAME: &'static str = DEPLOY_STORAGE_QUARANTINE_DB;
}

#[derive(Clone)]
pub struct RejectedDeployBufferName;

impl DeployStoreName for RejectedDeployBufferName {
    const NAME: &'static str = REJECTED_DEPLOY_BUFFER_DB;
    const QUARANTINE_NAME: &'static str = REJECTED_DEPLOY_BUFFER_QUARANTINE_DB;
    const SIZE_WARNING_THRESHOLD: Option<usize> = Some(1_000);
}

#[derive(Clone)]
pub struct KeyValueDeployStore<N: DeployStoreName> {
    pub store: KeyValueTypedStoreImpl<ByteString, Signed<DeployData>>,
    quarantine: DeployRecordQuarantine,
    metadata: Arc<parking_lot::Mutex<MetadataCache>>,
    _name: PhantomData<N>,
}

pub type KeyValueDeployStorage = KeyValueDeployStore<DeployStorageName>;
/// Per-node local buffer of deploys rejected during multi-parent merge.
///
/// When the merge algorithm drops a deploy from the canonical merged state,
/// its data is placed here so the block creator can re-propose it in a
/// subsequent block. Each validator maintains its own buffer; there is no
/// cross-validator coordination.
pub type KeyValueRejectedDeployBuffer = KeyValueDeployStore<RejectedDeployBufferName>;

impl<N: DeployStoreName> KeyValueDeployStore<N> {
    pub async fn new(kvm: &mut impl KeyValueStoreManager) -> Result<Self, KvStoreError> {
        let kv_store = kvm.store(N::NAME.to_string()).await?;
        let quarantine_kv_store = kvm.store(N::QUARANTINE_NAME.to_string()).await?;
        Self::from_stores(kv_store, quarantine_kv_store)
    }

    pub fn from_stores(
        store: Arc<dyn KeyValueStore>,
        quarantine: Arc<dyn KeyValueStore>,
    ) -> Result<Self, KvStoreError> {
        let storage = Self {
            store: KeyValueTypedStoreImpl::with_value_codec(
                store,
                super::deploy_codec::encode,
                super::deploy_codec::decode,
            ),
            quarantine: DeployRecordQuarantine::new(N::NAME, quarantine),
            metadata: Arc::default(),
            _name: PhantomData,
        };
        storage.quarantine.restore_readable(&storage.store)?;
        Ok(storage)
    }

    pub fn metadata_snapshot(&self) -> Result<MetadataSnapshot, KvStoreError> {
        let mut cache = self.metadata.lock();
        for _ in 0..3 {
            let before = store_revision(self.store.raw_store());
            if cache.initialized && before.is_some() && cache.revision == before {
                return Ok(cache.snapshot.clone());
            }
            let entries: imbl::HashMap<_, _> = self
                .read_all()?
                .iter()
                .map(|deploy| (deploy.sig.to_vec(), DeployMetadata::from(deploy)))
                .collect();
            let after = store_revision(self.store.raw_store());
            if before != after {
                continue;
            }
            if !cache.initialized || entries != cache.snapshot.entries {
                cache.snapshot.generation = cache.snapshot.generation.wrapping_add(1);
                cache.snapshot.entries = entries;
            }
            cache.snapshot.parent_generation = None;
            cache.snapshot.additions.clear();
            cache.snapshot.removals.clear();
            cache.initialized = true;
            cache.revision = after;
            return Ok(cache.snapshot.clone());
        }
        cache.revision = None;
        Err(KvStoreError::InvalidArgument(
            "Deploy storage changed during metadata refresh".into(),
        ))
    }

    pub fn add(&self, deploys: Vec<Signed<DeployData>>) -> Result<(), KvStoreError> {
        let mut cache = self.metadata.lock();
        let before = store_revision(self.store.raw_store());
        let additions = deploys.iter().map(DeployMetadata::from).collect();
        let result = self
            .store
            .put(deploys.into_iter().map(|d| (d.sig.to_vec(), d)).collect());
        cache.update(
            before,
            store_revision(self.store.raw_store()),
            1,
            additions,
            Vec::new(),
        );
        if result.is_err() {
            cache.revision = None;
        }
        result
    }

    pub fn add_if_absent(&self, deploy: Signed<DeployData>) -> Result<bool, KvStoreError> {
        let mut cache = self.metadata.lock();
        let before = store_revision(self.store.raw_store());
        let metadata = DeployMetadata::from(&deploy);
        let result = self.store.put_one_if_absent(deploy.sig.to_vec(), deploy);
        let writes = usize::from(matches!(result, Ok(true)));
        cache.update(
            before,
            store_revision(self.store.raw_store()),
            writes,
            vec![metadata],
            Vec::new(),
        );
        if result.is_err() {
            cache.revision = None;
        }
        result
    }

    pub fn contains_sig(&self, sig: &[u8]) -> Result<bool, KvStoreError> {
        let key: ByteString = sig.to_vec();
        Ok(self
            .store
            .contains(vec![key])?
            .into_iter()
            .next()
            .unwrap_or(false))
    }

    pub fn sigs(&self) -> Result<Vec<ByteString>, KvStoreError> {
        let mut sigs = Vec::new();
        self.store.raw_store().iterate_while(&mut |key, _| {
            sigs.push(self.store.decode_key(&key)?);
            Ok(true)
        })?;
        Ok(sigs)
    }

    pub fn remove(&self, deploys: Vec<Signed<DeployData>>) -> Result<(), KvStoreError> {
        self.remove_signatures(deploys.into_iter().map(|d| d.sig.to_vec()).collect())
    }

    fn remove_signatures(&self, signatures: Vec<Vec<u8>>) -> Result<(), KvStoreError> {
        let mut cache = self.metadata.lock();
        let before = store_revision(self.store.raw_store());
        let result = self.store.delete(signatures.clone());
        cache.update(
            before,
            store_revision(self.store.raw_store()),
            1,
            Vec::new(),
            signatures,
        );
        if result.is_err() {
            cache.revision = None;
        }
        result
    }

    pub fn remove_by_sig(&self, sig: &[u8]) -> Result<bool, KvStoreError> {
        let mut cache = self.metadata.lock();
        let before = store_revision(self.store.raw_store());
        let key = self.store.encode_key(&sig.to_vec())?;
        let result = self
            .store
            .raw_store()
            .delete(vec![key])
            .map(|count| count > 0);
        cache.update(
            before,
            store_revision(self.store.raw_store()),
            1,
            Vec::new(),
            vec![sig.to_vec()],
        );
        if result.is_err() {
            cache.revision = None;
        }
        result
    }

    pub fn any<F>(&self, predicate: F) -> Result<bool, KvStoreError>
    where F: FnMut(&Signed<DeployData>) -> Result<bool, KvStoreError> {
        self.quarantine.any(&self.store, predicate)
    }

    pub fn read_all(&self) -> Result<HashSet<Signed<DeployData>>, KvStoreError> {
        let all = self.quarantine.read_all(&self.store)?;
        metrics::gauge!(DEPLOY_STORE_SIZE_METRIC, "store" => N::NAME).set(all.len() as f64);
        metrics::counter!(DEPLOY_STORE_READ_ALL_DECODED_METRIC, "store" => N::NAME)
            .increment(all.len() as u64);
        if let Some(limit) = N::SIZE_WARNING_THRESHOLD {
            if all.len() > limit {
                tracing::warn!(
                    store = N::NAME,
                    size = all.len(),
                    limit,
                    "deploy store above size warning threshold"
                );
            }
        }
        Ok(all)
    }

    /// Check if the storage contains any pending deploys. O(1) time and space.
    pub fn non_empty(&self) -> Result<bool, KvStoreError> { self.store.non_empty() }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Barrier};

    use crypto::rust::private_key::PrivateKey;
    use crypto::rust::signatures::secp256k1::Secp256k1;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use rspace_plus_plus::rspace::shared::in_mem_key_value_store::InMemoryKeyValueStore;
    use rspace_plus_plus::rspace::shared::in_mem_store_manager::InMemoryStoreManager;
    use shared::rust::store::key_value_store::KeyValueStore;

    use super::*;

    fn deploy(time_stamp: i64) -> Signed<DeployData> {
        Signed::create(
            DeployData {
                term: "Nil".to_string(),
                time_stamp,
                phlo_price: 1,
                phlo_limit: 100_000,
                valid_after_block_number: 0,
                shard_id: "root".to_string(),
                expiration_timestamp: None,
                parameters: Vec::new(),
            },
            Box::new(Secp256k1),
            PrivateKey::from_bytes(&[1; 32]),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn storage_round_trips_add_contains_read_and_remove() {
        let mut kvm = InMemoryStoreManager::new();
        let storage = KeyValueDeployStorage::new(&mut kvm).await.unwrap();
        assert!(!storage.non_empty().unwrap());

        let (d1, d2) = (deploy(1), deploy(2));
        storage.add(vec![d1.clone(), d2.clone()]).unwrap();

        assert!(storage.non_empty().unwrap());
        assert!(storage.contains_sig(&d1.sig).unwrap());
        assert!(!storage.contains_sig(&[0u8; 64]).unwrap());
        assert_eq!(
            storage.read_all().unwrap(),
            HashSet::from([d1.clone(), d2.clone()])
        );

        assert!(storage.any(|d| Ok(d.data.time_stamp == 2)).unwrap());
        assert!(!storage.any(|d| Ok(d.data.time_stamp == 99)).unwrap());

        storage.remove(vec![d2]).unwrap();
        assert_eq!(storage.read_all().unwrap(), HashSet::from([d1.clone()]));

        assert!(storage.remove_by_sig(&d1.sig).unwrap());
        assert!(!storage.remove_by_sig(&d1.sig).unwrap());
        assert!(!storage.non_empty().unwrap());
    }

    async fn buffer() -> KeyValueRejectedDeployBuffer {
        let mut kvm = InMemoryStoreManager::new();
        KeyValueRejectedDeployBuffer::new(&mut kvm).await.unwrap()
    }

    #[tokio::test]
    async fn add_read_all_and_non_empty() {
        let buffer = buffer().await;
        assert!(!buffer.non_empty().unwrap());

        let (d1, d2) = (deploy(1), deploy(2));
        buffer.add(vec![d1.clone(), d2.clone()]).unwrap();

        assert!(buffer.non_empty().unwrap());
        assert_eq!(buffer.read_all().unwrap(), HashSet::from([d1, d2]));
    }

    #[tokio::test]
    async fn remove_deletes_listed_deploys() {
        let buffer = buffer().await;
        let (d1, d2) = (deploy(1), deploy(2));
        buffer.add(vec![d1.clone(), d2.clone()]).unwrap();

        buffer.remove(vec![d2]).unwrap();
        assert_eq!(buffer.read_all().unwrap(), HashSet::from([d1]));
    }

    #[tokio::test]
    async fn remove_by_sig_reports_presence() {
        let buffer = buffer().await;
        let d1 = deploy(1);
        buffer.add(vec![d1.clone()]).unwrap();

        assert!(buffer.remove_by_sig(&d1.sig).unwrap());
        assert!(!buffer.remove_by_sig(&d1.sig).unwrap());
        assert!(!buffer.contains_sig(&d1.sig).unwrap());
        assert!(!buffer.non_empty().unwrap());
    }

    #[test]
    fn concurrent_signature_removals_report_one_actual_delete() {
        let storage = KeyValueDeployStorage::from_stores(
            Arc::new(InMemoryKeyValueStore::new()),
            Arc::new(InMemoryKeyValueStore::new()),
        )
        .unwrap();
        let valid = deploy(1);
        storage.add(vec![valid.clone()]).unwrap();
        let barrier = Arc::new(Barrier::new(16));
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let storage = storage.clone();
                let sig = valid.sig.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    storage.remove_by_sig(&sig).unwrap()
                })
            })
            .collect();
        assert_eq!(
            handles
                .into_iter()
                .map(|handle| usize::from(handle.join().unwrap()))
                .sum::<usize>(),
            1
        );
        assert!(!storage.contains_sig(&valid.sig).unwrap());
    }

    #[tokio::test]
    async fn read_all_reports_the_size_of_each_store() {
        let mut kvm = InMemoryStoreManager::new();
        let storage = KeyValueDeployStorage::new(&mut kvm).await.unwrap();
        let buffer = KeyValueRejectedDeployBuffer::new(&mut kvm).await.unwrap();
        storage.add(vec![deploy(1), deploy(2)]).unwrap();
        buffer.add(vec![deploy(3)]).unwrap();

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            storage.read_all().unwrap();
            buffer.read_all().unwrap();
        });

        let sizes: HashMap<String, f64> = snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .filter(|(key, ..)| key.key().name() == DEPLOY_STORE_SIZE_METRIC)
            .filter_map(|(key, _, _, value)| match value {
                DebugValue::Gauge(size) => key
                    .key()
                    .labels()
                    .find(|label| label.key() == "store")
                    .map(|label| (label.value().to_string(), size.into_inner())),
                _ => None,
            })
            .collect();
        assert_eq!(
            sizes,
            HashMap::from([
                ("deploy_storage".to_string(), 2.0),
                ("rejected_deploy_buffer".to_string(), 1.0),
            ])
        );
    }

    #[tokio::test]
    async fn read_all_counts_each_decoded_deploy_of_each_store() {
        let mut kvm = InMemoryStoreManager::new();
        let storage = KeyValueDeployStorage::new(&mut kvm).await.unwrap();
        let buffer = KeyValueRejectedDeployBuffer::new(&mut kvm).await.unwrap();
        storage.add(vec![deploy(1), deploy(2)]).unwrap();
        buffer.add(vec![deploy(3)]).unwrap();

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            storage.read_all().unwrap();
            storage.read_all().unwrap();
            buffer.read_all().unwrap();
        });

        let decoded: HashMap<String, u64> = snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .filter(|(key, ..)| key.key().name() == DEPLOY_STORE_READ_ALL_DECODED_METRIC)
            .filter_map(|(key, _, _, value)| match value {
                DebugValue::Counter(count) => key
                    .key()
                    .labels()
                    .find(|label| label.key() == "store")
                    .map(|label| (label.value().to_string(), count)),
                _ => None,
            })
            .collect();
        assert_eq!(
            decoded,
            HashMap::from([
                ("deploy_storage".to_string(), 4),
                ("rejected_deploy_buffer".to_string(), 1),
            ])
        );
    }

    #[tokio::test]
    async fn add_if_absent_reports_the_duplicate() {
        let mut kvm = InMemoryStoreManager::new();
        let storage = KeyValueDeployStorage::new(&mut kvm).await.unwrap();
        let d1 = deploy(1);
        assert!(storage.add_if_absent(d1.clone()).unwrap());
        assert!(!storage.add_if_absent(d1).unwrap());
        assert_eq!(storage.read_all().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn the_two_stores_open_separate_lmdb_stores() {
        let mut kvm = InMemoryStoreManager::new();
        let storage = KeyValueDeployStorage::new(&mut kvm).await.unwrap();
        let buffer = KeyValueRejectedDeployBuffer::new(&mut kvm).await.unwrap();
        storage.add(vec![deploy(1)]).unwrap();
        assert!(storage.non_empty().unwrap());
        assert!(!buffer.non_empty().unwrap());
    }

    #[test]
    fn add_if_absent_is_atomic_across_storage_handles() {
        let store: Arc<dyn KeyValueStore> = Arc::new(InMemoryKeyValueStore::new());
        let storage =
            KeyValueDeployStorage::from_stores(store, Arc::new(InMemoryKeyValueStore::new()))
                .unwrap();
        let deploy = Signed::create(
            DeployData {
                term: "Nil".to_string(),
                time_stamp: 1,
                phlo_price: 1,
                phlo_limit: 100_000,
                valid_after_block_number: 0,
                shard_id: "root".to_string(),
                expiration_timestamp: None,
                parameters: Vec::new(),
            },
            Box::new(Secp256k1),
            PrivateKey::from_bytes(&[1; 32]),
        )
        .unwrap();
        let barrier = Arc::new(Barrier::new(32));

        let handles = (0..32)
            .map(|_| {
                let storage = storage.clone();
                let deploy = deploy.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    storage.add_if_absent(deploy).unwrap()
                })
            })
            .collect::<Vec<_>>();

        let inserted = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|inserted| *inserted)
            .count();

        assert_eq!(inserted, 1);
        assert_eq!(storage.read_all().unwrap().len(), 1);
    }

    mod metadata_cache {
        use rspace_plus_plus::rspace::shared::lmdb_dir_store_manager::{
            Db, LmdbDirStoreManager, LmdbEnvConfig,
        };

        use super::{
            deploy, KeyValueDeployStorage, KeyValueStoreManager, DEPLOY_STORAGE_DB,
            DEPLOY_STORAGE_QUARANTINE_DB,
        };

        async fn storage(path: &std::path::Path) -> KeyValueDeployStorage {
            let mapping = [DEPLOY_STORAGE_DB, DEPLOY_STORAGE_QUARANTINE_DB]
                .into_iter()
                .map(|name| {
                    (
                        Db::new(name.into(), None),
                        LmdbEnvConfig::new("deploys".into(), 10 * 1024 * 1024),
                    )
                })
                .collect();
            let mut manager = LmdbDirStoreManager::new(path.to_path_buf(), mapping);
            let store = manager.store(DEPLOY_STORAGE_DB.into()).await.unwrap();
            let quarantine = manager
                .store(DEPLOY_STORAGE_QUARANTINE_DB.into())
                .await
                .unwrap();
            KeyValueDeployStorage::from_stores(store, quarantine).unwrap()
        }

        #[tokio::test]
        async fn metadata_tracks_writes_and_removals_from_cloned_handles() {
            let dir = tempfile::tempdir().unwrap();
            let pool = storage(dir.path()).await;
            let proposer = pool.clone();
            let initial = pool.metadata_snapshot().unwrap();
            let first = deploy(1);
            pool.add(vec![first.clone()]).unwrap();
            let added = pool.metadata_snapshot().unwrap();
            assert_eq!(added.entries.len(), 1);
            assert_eq!(added.parent_generation, Some(initial.generation));
            assert_eq!(
                proposer.metadata_snapshot().unwrap().generation,
                added.generation
            );
            assert!(!proposer.add_if_absent(first.clone()).unwrap());
            assert_eq!(
                pool.metadata_snapshot().unwrap().generation,
                added.generation
            );
            proposer.remove_by_sig(&first.sig).unwrap();
            let removed = pool.metadata_snapshot().unwrap();
            assert!(removed.entries.is_empty());
            assert_ne!(removed.generation, added.generation);
            assert_eq!(removed.parent_generation, Some(added.generation));
        }

        #[tokio::test]
        async fn raw_and_independently_opened_writes_force_a_metadata_refresh() {
            let dir = tempfile::tempdir().unwrap();
            let pool = storage(dir.path()).await;
            let initial = pool.metadata_snapshot().unwrap();
            let first = deploy(1);
            pool.store
                .put_one(first.sig.to_vec(), first.clone())
                .unwrap();
            let added = pool.metadata_snapshot().unwrap();
            assert_eq!(added.entries.len(), 1);
            assert_ne!(added.generation, initial.generation);
            assert_eq!(added.parent_generation, None);
            let independent = storage(dir.path()).await;
            independent.add(vec![deploy(2)]).unwrap();
            assert_eq!(pool.metadata_snapshot().unwrap().entries.len(), 2);
            independent.remove_by_sig(&first.sig).unwrap();
            assert!(!pool
                .metadata_snapshot()
                .unwrap()
                .entries
                .contains_key(&first.sig.to_vec()));
        }

        #[tokio::test]
        async fn unchanged_metadata_keeps_its_generation_after_an_unrelated_write() {
            let dir = tempfile::tempdir().unwrap();
            let pool = storage(dir.path()).await;
            let initial = pool.metadata_snapshot().unwrap();
            let independent = storage(dir.path()).await;
            let first = deploy(1);
            independent.add(vec![first.clone()]).unwrap();
            independent.remove_by_sig(&first.sig).unwrap();
            let refreshed = pool.metadata_snapshot().unwrap();
            assert!(refreshed.entries.is_empty());
            assert_eq!(refreshed.generation, initial.generation);
            assert_eq!(refreshed.parent_generation, None);
        }

        #[tokio::test]
        async fn restart_rebuilds_metadata_from_the_persistent_pool() {
            let dir = tempfile::tempdir().unwrap();
            let signature = {
                let pool = storage(dir.path()).await;
                let first = deploy(1);
                pool.add(vec![first.clone()]).unwrap();
                pool.metadata_snapshot().unwrap();
                first.sig.to_vec()
            };
            let pool = storage(dir.path()).await;
            assert!(pool
                .metadata_snapshot()
                .unwrap()
                .entries
                .contains_key(&signature));
        }

        #[tokio::test]
        async fn warm_metadata_does_not_decode_signed_pool_records() {
            use metrics_util::debugging::DebuggingRecorder;
            let dir = tempfile::tempdir().unwrap();
            let pool = storage(dir.path()).await;
            pool.add((0..24).map(deploy).collect()).unwrap();
            pool.metadata_snapshot().unwrap();
            let recorder = DebuggingRecorder::new();
            let snapshots = recorder.snapshotter();
            metrics::with_local_recorder(&recorder, || {
                for timestamp in 24..32 {
                    assert_eq!(
                        pool.metadata_snapshot().unwrap().entries.len(),
                        timestamp as usize
                    );
                    pool.add_if_absent(deploy(timestamp)).unwrap();
                    pool.metadata_snapshot().unwrap();
                }
            });
            assert!(snapshots
                .snapshot()
                .into_vec()
                .iter()
                .all(|(key, ..)| { key.key().name() != "deploy-store.read-all.decoded" }));
            assert_eq!(pool.metadata_snapshot().unwrap().entries.len(), 32);
        }
    }
}
