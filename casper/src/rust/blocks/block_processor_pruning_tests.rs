use block_storage::rust::dag::block_dag_key_value_storage::InsertMode;
use comm::rust::peer_node::{NodeIdentifier, PeerNode};
use comm::rust::rp::connect::Connections;
use comm::rust::test_instances::{create_rp_conf_ask, TransportLayerStub};
use models::rust::block_implicits::get_random_block;
use rspace_plus_plus::rspace::shared::in_mem_store_manager::InMemoryStoreManager;

use super::*;
use crate::rust::engine::block_retriever::{
    AdmitHashResult, AdmitHashStatus, MAX_RETRIES_PER_HASH,
};
use crate::rust::protocol::{extract_packet_from_protocol, verify_block_request};

struct Fixture {
    dependencies: BlockProcessorDependencies<TransportLayerStub>,
    peer: PeerNode,
    parent: BlockHash,
    child: BlockHash,
}

impl Fixture {
    async fn new() -> Self {
        let mut kvm = InMemoryStoreManager::new();
        let block_store = KeyValueBlockStore::create_from_kvm(&mut kvm).await.unwrap();
        let dag = BlockDagKeyValueStorage::new(&mut kvm).await.unwrap();
        let buffer = CasperBufferKeyValueStorage::new_from_kvm(&mut kvm)
            .await
            .unwrap();
        let genesis = get_random_block(
            Some(0),
            None,
            None,
            None,
            None,
            None,
            None,
            Some(vec![]),
            None,
            None,
            None,
            Some(vec![]),
            None,
            None,
        );
        block_store.put_block_message(&genesis).unwrap();
        dag.insert(&genesis, InsertMode::Approved).unwrap();

        let local = PeerNode::new(
            NodeIdentifier {
                key: vec![1; 20].into(),
            },
            "local".to_string(),
            40400,
            40404,
        );
        let peer = PeerNode::new(
            NodeIdentifier {
                key: vec![2; 20].into(),
            },
            "peer".to_string(),
            40400,
            40404,
        );
        let connections = ConnectionsCell {
            peers: Arc::new(Mutex::new(Connections::from_vec(vec![peer.clone()]))),
        };
        let conf = create_rp_conf_ask(local, None, None);
        let transport = Arc::new(TransportLayerStub::new());
        let retriever = BlockRetriever::new(
            Arc::new(Mutex::new(HashMap::new())),
            transport.clone(),
            connections.clone(),
            conf.clone(),
        );
        let parent = BlockHash::from(vec![3; 32]);
        let child = BlockHash::from(vec![4; 32]);
        buffer
            .add_relation(
                BlockHashSerde(parent.clone()),
                BlockHashSerde(child.clone()),
            )
            .unwrap();
        let dependencies = BlockProcessorDependencies::new(
            block_store,
            buffer,
            dag,
            retriever,
            transport,
            connections,
            conf,
            None,
        );

        Self {
            dependencies,
            peer,
            parent,
            child,
        }
    }

    async fn request_parent(&self) -> AdmitHashResult {
        self.dependencies
            .block_retriever
            .admit_hash(
                self.parent.clone(),
                Some(self.peer.clone()),
                AdmitHashReason::MissingDependencyRequested,
            )
            .await
            .unwrap()
    }

    fn prune(&self) {
        self.dependencies.enforce_casper_buffer_limit(0).unwrap();
        assert_eq!(self.dependencies.casper_buffer.approx_node_count(), 0);
        assert!(!self
            .dependencies
            .casper_buffer
            .is_pendant(&BlockHashSerde(self.parent.clone())));
        assert!(!self
            .dependencies
            .casper_buffer
            .contains(&BlockHashSerde(self.child.clone())));
    }
}

#[tokio::test]
async fn overflow_prune_keeps_an_unreceived_dependency_retryable() {
    let fixture = Fixture::new().await;
    fixture.request_parent().await;
    let retriever = &fixture.dependencies.block_retriever;
    retriever
        .set_retry_attempts_for_test(&fixture.parent, 3)
        .unwrap();

    fixture.prune();

    let mut request = retriever
        .get_request_state_for_test(&fixture.parent)
        .await
        .unwrap()
        .expect("Buffer pruning must keep the pending parent request");
    assert!(!request.received);
    assert!(request.requested_as_dependency);
    assert_eq!(request.waiting_list, vec![fixture.peer.clone()]);
    assert_eq!(
        retriever.retry_attempts_for_test(&fixture.parent).unwrap(),
        3
    );

    request.timestamp = 0;
    retriever
        .set_request_state_for_test(fixture.parent.clone(), request)
        .await
        .unwrap();
    fixture.dependencies.transport.reset();
    retriever.request_all(Duration::ZERO).await.unwrap();

    let parent_requested = (0..fixture.dependencies.transport.request_count())
        .filter_map(|index| fixture.dependencies.transport.get_request(index))
        .any(|(peer, protocol)| {
            peer == fixture.peer
                && extract_packet_from_protocol(&protocol)
                    .is_ok_and(|packet| verify_block_request(&packet, &fixture.parent).is_ok())
        });
    assert!(
        parent_requested,
        "The retry must request the missing parent from its peer"
    );
}

#[tokio::test]
async fn overflow_prune_reopens_a_received_block_for_another_request() {
    let fixture = Fixture::new().await;
    let retriever = &fixture.dependencies.block_retriever;
    retriever.ack_receive(fixture.parent.clone()).await.unwrap();
    assert!(retriever.is_received(fixture.parent.clone()).await.unwrap());

    fixture.prune();

    assert!(retriever
        .get_request_state_for_test(&fixture.parent)
        .await
        .unwrap()
        .is_none());
    fixture.dependencies.transport.reset();
    let result = fixture.request_parent().await;
    assert_eq!(result.status, AdmitHashStatus::NewRequestAdded);
    assert_eq!(fixture.dependencies.transport.request_count(), 1);
}

#[tokio::test]
async fn overflow_prune_preserves_the_retry_quarantine() {
    let fixture = Fixture::new().await;
    fixture.request_parent().await;
    let retriever = &fixture.dependencies.block_retriever;
    retriever
        .set_retry_attempts_for_test(&fixture.parent, MAX_RETRIES_PER_HASH)
        .unwrap();
    retriever
        .recover_dependency(fixture.parent.clone())
        .await
        .unwrap();
    assert!(retriever
        .get_request_state_for_test(&fixture.parent)
        .await
        .unwrap()
        .is_none());
    fixture.dependencies.transport.reset();
    assert_eq!(
        fixture.request_parent().await.status,
        AdmitHashStatus::Ignore
    );

    fixture.prune();

    assert_eq!(
        fixture.request_parent().await.status,
        AdmitHashStatus::Ignore
    );
    assert_eq!(fixture.dependencies.transport.request_count(), 0);
    assert_eq!(
        retriever.retry_attempts_for_test(&fixture.parent).unwrap(),
        MAX_RETRIES_PER_HASH
    );
}
