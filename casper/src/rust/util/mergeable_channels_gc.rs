//! Mergeable Channels Garbage Collection
//!
//! Garbage collects mergeable channel data for blocks that are provably unreachable.
//! This is required for multi-parent mode where immediate deletion during finalization
//! can cause data races.

use std::collections::HashSet;

use block_storage::rust::dag::block_dag_key_value_storage::KeyValueDagRepresentation;
use block_storage::rust::key_value_block_store::KeyValueBlockStore;
use models::rust::block_hash::BlockHash;
use shared::rust::store::key_value_store::KvStoreError;

use crate::rust::casper::CasperShardConf;
use crate::rust::metrics_constants::MERGEABLE_CHANNELS_GC_METRICS_SOURCE;
use crate::rust::util::rholang::runtime_manager::RuntimeManager;

/// `next_height`: heights below it are fully handled and never revisited.
/// `processed` stays bounded to the retention window above it, not to chain age.
#[derive(Default)]
pub struct GcState {
    next_height: i64,
    processed: HashSet<BlockHash>,
}

impl GcState {
    pub fn new() -> Self { Self::default() }
}

struct MainChain {
    latest: BlockHash,
    blocks: HashSet<BlockHash>,
}

/// Garbage collects mergeable channel data for blocks that are provably unreachable.
///
/// A block's mergeable data is safe to delete when:
/// 1. The block is finalized
/// 2. All validators' latest messages are descendants of the block's children
/// 3. The block is deeper than maxParentDepth + depthBuffer from current tips
pub fn collect_garbage(
    dag: &KeyValueDagRepresentation,
    block_store: &KeyValueBlockStore,
    runtime_manager: &std::sync::Arc<RuntimeManager>,
    casper_shard_conf: &CasperShardConf,
    state: &mut GcState,
) -> Result<usize, KvStoreError> {
    let pass_started = std::time::Instant::now();
    let result = run_pass(dag, block_store, runtime_manager, casper_shard_conf, state);
    metrics::histogram!("mergeable_channels_gc.pass.time", "source" => MERGEABLE_CHANNELS_GC_METRICS_SOURCE)
        .record(pass_started.elapsed().as_secs_f64());
    result
}

fn run_pass(
    dag: &KeyValueDagRepresentation,
    block_store: &KeyValueBlockStore,
    runtime_manager: &std::sync::Arc<RuntimeManager>,
    casper_shard_conf: &CasperShardConf,
    state: &mut GcState,
) -> Result<usize, KvStoreError> {
    let max_block_number = dag.latest_block_number();
    if state.next_height > max_block_number {
        tracing::debug!("Mergeable channels GC: nothing above watermark");
        return Ok(0);
    }

    let max_allowed_depth = (casper_shard_conf.max_parent_depth as i64)
        + (casper_shard_conf.mergeable_channels_gc_depth_buffer as i64);
    let main_chains = build_main_chains(dag, state.next_height)?;
    let levels = dag.topo_sort(state.next_height, None)?;

    let mut deleted_count = 0;
    let mut contiguous = true;

    for level in levels {
        if level.is_empty() {
            continue;
        }

        let mut level_complete = true;
        for block_hash in &level {
            if state.processed.contains(block_hash) {
                continue;
            }

            if !is_safe_to_delete(
                dag,
                block_hash,
                max_block_number,
                max_allowed_depth,
                &main_chains,
            )? {
                level_complete = false;
                continue;
            }

            if let Some(block) = block_store.get(block_hash)? {
                let deleted = runtime_manager
                    .delete_mergeable_channels(
                        &block.body.state.post_state_hash,
                        block.sender.clone(),
                        block.seq_num,
                    )
                    .map_err(|e| KvStoreError::IoError(e.to_string()))?;

                if deleted {
                    deleted_count += 1;
                    tracing::debug!(
                        "GC: Deleted mergeable data for block {}",
                        hex::encode(block_hash)
                    );
                }
            }

            state.processed.insert(block_hash.clone());
        }

        if contiguous && level_complete {
            let level_height = dag.lookup_unsafe(&level[0])?.block_number;
            state.next_height = level_height + 1;
            for block_hash in &level {
                state.processed.remove(block_hash);
            }
        } else {
            contiguous = false;
        }
    }

    if deleted_count > 0 {
        metrics::counter!("mergeable_channels_gc_deleted").increment(deleted_count as u64);
        tracing::info!(
            "Mergeable channels GC: Deleted {} blocks' data",
            deleted_count
        );
    } else {
        tracing::debug!("Mergeable channels GC: No data to delete");
    }

    Ok(deleted_count)
}

/// Stops at `floor_height` — candidates never go below it and children only
/// get higher, so nothing lower is ever queried.
fn build_main_chains(
    dag: &KeyValueDagRepresentation,
    floor_height: i64,
) -> Result<Vec<MainChain>, KvStoreError> {
    dag.latest_message_hashes()
        .values()
        .map(|latest| {
            let mut blocks = HashSet::new();
            let mut current = Some(latest.clone());
            while let Some(hash) = current {
                if dag.block_number_unsafe(&hash)? < floor_height {
                    break;
                }
                if !blocks.insert(hash.clone()) {
                    break;
                }
                current = dag.main_parent(&hash);
            }
            Ok(MainChain {
                latest: latest.clone(),
                blocks,
            })
        })
        .collect()
}

fn is_safe_to_delete(
    dag: &KeyValueDagRepresentation,
    block_hash: &BlockHash,
    max_block_number: i64,
    max_allowed_depth: i64,
    main_chains: &[MainChain],
) -> Result<bool, KvStoreError> {
    // 1. Check if block is finalized
    if !dag.is_finalized(block_hash) {
        return Ok(false);
    }

    // 2. Check depth constraint
    let block_meta = dag.lookup_unsafe(block_hash)?;
    let depth_from_tip = max_block_number - block_meta.block_number;

    if depth_from_tip <= max_allowed_depth {
        return Ok(false);
    }

    // 3. Check if all validators have moved past this block
    let children = match dag.children(block_hash) {
        Some(children_set) => children_set,
        None => return Ok(false), // No children means no one can have moved past
    };

    if children.is_empty() {
        return Ok(false);
    }

    for main_chain in main_chains {
        if &main_chain.latest == block_hash {
            // Validator's latest is still this block
            return Ok(false);
        }

        let found_in_child_chain = children
            .iter()
            .any(|child_hash| main_chain.blocks.contains(child_hash));

        if !found_in_child_chain {
            return Ok(false);
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::rust::test_utils::helper::block_dag_storage_fixture::with_storage;
    use crate::rust::test_utils::helper::block_generator::{
        create_block_fast, create_genesis_block,
    };
    use crate::rust::test_utils::util::rholang::resources::mk_runtime_manager;

    fn shard_conf(max_parent_depth: i32, depth_buffer: i32) -> CasperShardConf {
        CasperShardConf {
            max_parent_depth,
            mergeable_channels_gc_depth_buffer: depth_buffer,
            enable_mergeable_channel_gc: true,
            ..CasperShardConf::new()
        }
    }

    // A single validator produces a linear chain of `count` blocks past genesis.
    // `create_block_fast` leaves `creator` at its default, so every block shares
    // one identity — this is the single-validator case `build_main_chains` is built for.
    async fn linear_chain(
        block_store: &mut block_storage::rust::key_value_block_store::KeyValueBlockStore,
        dag_storage: &mut block_storage::rust::test::indexed_block_dag_storage::IndexedBlockDagStorage,
        count: usize,
    ) -> Vec<models::rust::casper::protocol::casper_message::BlockMessage> {
        let genesis = create_genesis_block(
            block_store,
            dag_storage,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let mut chain = vec![genesis.clone()];
        let mut parent = genesis.clone();
        for _ in 0..count {
            let block = create_block_fast(
                block_store,
                dag_storage,
                vec![parent.block_hash.clone()],
                &genesis,
            );
            chain.push(block.clone());
            parent = block;
        }
        chain
    }

    #[tokio::test]
    async fn is_safe_to_delete_respects_depth_and_main_chain_reachability() {
        with_storage(|mut block_store, mut dag_storage| async move {
            let chain = linear_chain(&mut block_store, &mut dag_storage, 6).await;
            let tip = chain.last().unwrap().clone();

            dag_storage
                .record_directly_finalized(tip.block_hash.clone(), 1.0, |_| async { Ok(()) })
                .await
                .unwrap();

            let dag = dag_storage.get_representation().unwrap();
            // `latest_block_number()` is one past the tip's own height (it is an
            // exclusive upper bound, used as such by `topo_sort`), so the tip's
            // own depth-from-tip is 1, not 0 — max_allowed_depth=2 is what
            // protects exactly {tip, tip's parent}.
            let conf = shard_conf(2, 0);
            let max_block_number = dag.latest_block_number();
            let max_allowed_depth =
                (conf.max_parent_depth as i64) + (conf.mergeable_channels_gc_depth_buffer as i64);
            let main_chains = build_main_chains(&dag, 0).unwrap();

            // Deep enough and finalized: everything except the tip and its
            // immediate parent.
            for block in &chain[0..=4] {
                assert!(
                    is_safe_to_delete(
                        &dag,
                        &block.block_hash,
                        max_block_number,
                        max_allowed_depth,
                        &main_chains
                    )
                    .unwrap(),
                    "block at height {} should be safe to delete",
                    dag.lookup_unsafe(&block.block_hash).unwrap().block_number
                );
            }
            // Too close to the tip: the depth guard must reject these regardless
            // of finalization or reachability.
            for block in &chain[5..=6] {
                assert!(
                    !is_safe_to_delete(
                        &dag,
                        &block.block_hash,
                        max_block_number,
                        max_allowed_depth,
                        &main_chains
                    )
                    .unwrap(),
                    "block too close to the tip must not be deletable"
                );
            }
        })
        .await;
    }

    #[tokio::test]
    async fn watermark_holds_at_a_height_that_is_not_yet_finalized() {
        with_storage(|mut block_store, mut dag_storage| async move {
            let runtime_manager = Arc::new(mk_runtime_manager("gc-watermark-test", None).await);
            let conf = shard_conf(0, 0); // max_allowed_depth = 0: anything but the tip qualifies
            let mut state = GcState::new();

            // genesis(h0) -> b1(h1) -> b2(h2) -> b3(h3, tip); finalize only up to b1.
            let chain = linear_chain(&mut block_store, &mut dag_storage, 3).await;
            dag_storage
                .record_directly_finalized(chain[1].block_hash.clone(), 1.0, |_| async { Ok(()) })
                .await
                .unwrap();

            {
                let dag = dag_storage.get_representation().unwrap();
                collect_garbage(&dag, &block_store, &runtime_manager, &conf, &mut state).unwrap();
            }
            // h2 (b2) is unfinalized, so the watermark must stop there rather
            // than skipping past it because a later height happened to qualify.
            assert_eq!(
                state.next_height, 2,
                "watermark must halt at the first height that is not fully handled"
            );

            // Extend the chain and finalize the rest; the previously-blocked
            // height must be picked up on the next pass, not skipped forever.
            let mut parent = chain.last().unwrap().clone();
            let genesis = chain[0].clone();
            let mut tail = Vec::new();
            for _ in 0..3 {
                let block = create_block_fast(
                    &mut block_store,
                    &mut dag_storage,
                    vec![parent.block_hash.clone()],
                    &genesis,
                );
                tail.push(block.clone());
                parent = block;
            }
            dag_storage
                .record_directly_finalized(parent.block_hash.clone(), 1.0, |_| async { Ok(()) })
                .await
                .unwrap();

            {
                let dag = dag_storage.get_representation().unwrap();
                collect_garbage(&dag, &block_store, &runtime_manager, &conf, &mut state).unwrap();
            }
            assert_eq!(
                state.next_height, 6,
                "watermark must advance past the previously-blocked height once it clears"
            );
        })
        .await;
    }
}
