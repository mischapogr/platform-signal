use super::*;
use object_store::{local::LocalFileSystem, memory::InMemory};
use tempfile::TempDir;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
#[tokio::test]
async fn ready_owner_reply_cannot_bypass_original_deadline() -> Result {
    let (reply, receive) = oneshot::channel();
    reply
        .send(Ok(()))
        .map_err(|_| "owner receiver disappeared")?;
    let mut context = context();
    context.deadline = Instant::now() - Duration::from_millis(1);
    assert_eq!(
        receive_owner_ready(receive, &context).await,
        Err(ObjectIoError::Timeout)
    );
    Ok(())
}
fn context() -> OperationContext {
    OperationContext::new(Duration::from_secs(5))
}
#[tokio::test]
async fn completed_create_reply_cannot_arrive_as_success_after_deadline() -> Result {
    let io = remote(ObjectIoLimits::default())?;
    let context = OperationContext::new(Duration::from_secs(2));
    let deadline = context.deadline;
    let mut request = Box::pin(io.create("query/late-reply", b"created before timeout", context));
    assert!(futures_util::poll!(request.as_mut()).is_pending());
    while io.metrics().processed == 0 || io.metrics().running != 0 {
        assert!(
            Instant::now() < deadline,
            "worker must complete before deadline"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    tokio::time::sleep_until(deadline + Duration::from_millis(2)).await;
    assert!(matches!(request.await, Err(ObjectIoError::Timeout)));
    assert_eq!(io.metrics().depth, 0);
    assert_eq!(io.metrics().rejected, 1);
    let discovery = io.discover("query/late-reply", self::context()).await?;
    assert_eq!(discovery.bytes(), b"created before timeout");
    drop(discovery);
    io.shutdown(self::context()).await?;
    Ok(())
}
fn remote(limits: ObjectIoLimits) -> Result<ObjectIo> {
    Ok(ObjectIo::remote(
        Arc::new(InMemory::new()),
        tokio::runtime::Handle::current(),
        limits,
    )?)
}
#[tokio::test]
async fn conditional_create_exact_read_and_owned_replies_hold_admission() -> Result {
    let io = remote(ObjectIoLimits::default())?;
    let expected = io
        .create("query/synthetic/data/one", b"preserved bytes", context())
        .await?;
    assert!(matches!(
        io.create(&expected.key, b"different bytes", context())
            .await,
        Err(ObjectIoError::Exists)
    ));
    let read = io.read_exact(&expected, context()).await?;
    assert_eq!(read.bytes(), b"preserved bytes");
    assert_eq!(read.reference(), &expected);
    assert_eq!(io.metrics().depth, 1);
    assert!(matches!(
        io.discover(&expected.key, context()).await,
        Err(ObjectIoError::Full)
    ));
    drop(read);
    let inventory = io.inventory("query/synthetic", context()).await?;
    assert_eq!(inventory.entries().len(), 1);
    assert_eq!(inventory.entries()[0].key, expected.key);
    assert_eq!(inventory.entries()[0].sha256, [0; 32]); // listing never authenticates content
    assert!(matches!(
        io.read_exact(&expected, context()).await,
        Err(ObjectIoError::Full)
    ));
    drop(inventory);
    let mut wrong = expected.clone();
    wrong.sha256[0] ^= 1;
    assert!(matches!(
        io.read_exact(&wrong, context()).await,
        Err(ObjectIoError::Corrupt)
    ));
    assert!(matches!(
        io.discover_bounded(&expected.key, 2, context()).await,
        Err(ObjectIoError::Corrupt)
    ));
    for _ in 0..100 {
        let read = io.read_exact(&expected, context()).await?;
        assert_eq!(read.bytes(), b"preserved bytes");
        drop(read);
    }
    assert_eq!(io.metrics().rejected, 5);
    io.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn fixed_local_worker_reopen_mutation_missing_and_version_fail_closed() -> Result {
    let root = TempDir::new()?;
    let backend = LocalFileSystem::new_with_prefix(root.path())?;
    let io = ObjectIo::local(backend, ObjectIoLimits::default())?;
    let expected = io
        .create("query/synthetic/data/one", b"original", context())
        .await?;
    let read = io.read_exact(&expected, context()).await?;
    assert_eq!(read.bytes(), b"original");
    drop(read);
    io.shutdown(context()).await?;
    let io = ObjectIo::local(
        LocalFileSystem::new_with_prefix(root.path())?,
        ObjectIoLimits::default(),
    )?;
    let read = io.read_exact(&expected, context()).await?;
    assert_eq!(read.reference(), &expected);
    drop(read);
    let mut wrong = expected.clone();
    wrong.version = Some("missing-version".into());
    assert!(io.read_exact(&wrong, context()).await.is_err());
    std::fs::write(root.path().join(&expected.key), b"changed!")?;
    assert!(io.read_exact(&expected, context()).await.is_err());
    let fresh = io.discover(&expected.key, context()).await?;
    assert_eq!(fresh.bytes(), b"changed!");
    drop(fresh);
    assert!(matches!(
        io.discover("query/synthetic/missing", context()).await,
        Err(ObjectIoError::NotFound)
    ));
    io.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn byte_inventory_context_and_key_limits_reject_without_overwrite() -> Result {
    let limits = ObjectIoLimits {
        bytes: 8,
        entries: 2,
        ..Default::default()
    };
    let io = remote(limits)?;
    assert!(matches!(
        io.create("query/a", b"012345678", context()).await,
        Err(ObjectIoError::Full)
    ));
    assert!(matches!(
        io.create("query/../a", b"ok", context()).await,
        Err(ObjectIoError::Corrupt)
    ));
    let cancelled = context();
    cancelled.cancellation.cancel();
    assert!(matches!(
        io.create("query/a", b"ok", cancelled).await,
        Err(ObjectIoError::Cancelled)
    ));
    assert_eq!(io.metrics().processed, 0);
    assert_eq!(io.metrics().rejected, 3);
    for key in ["query/a", "query/b", "query/c"] {
        io.create(key, b"ok", context()).await?;
    }
    assert!(matches!(
        io.inventory("query", context()).await,
        Err(ObjectIoError::Full)
    ));
    let mut reference = io.create("other/a", b"ok", context()).await?;
    reference.version = Some("v".repeat(257));
    assert!(matches!(
        io.read_exact(&reference, context()).await,
        Err(ObjectIoError::Corrupt)
    ));
    assert_eq!(io.metrics().rejected, 5);
    io.shutdown(context()).await?;
    assert!(matches!(
        io.discover("query/a", context()).await,
        Err(ObjectIoError::Closed)
    ));
    assert_eq!(io.metrics().rejected, 6);
    Ok(())
}
#[tokio::test]
async fn caller_timeout_cannot_release_non_cancellable_physical_work() -> Result {
    let root = TempDir::new()?;
    let control = TempDir::new()?;
    let owner = SmallOwnerConfig {
        directory: control.path().to_path_buf(),
        stream_id: uuid::Uuid::new_v4(),
        backend_id: uuid::Uuid::new_v4(),
    };
    let io = Arc::new(
        ObjectIo::open_small_local(
            &owner,
            LocalFileSystem::new_with_prefix(root.path())?,
            ObjectIoLimits::default(),
            context(),
        )
        .await?,
    );
    let (entered, receive) = oneshot::channel();
    let (release, wait) = std::sync::mpsc::sync_channel(0);
    let child = io.clone();
    let request = tokio::spawn(async move {
        let mut context = OperationContext::new(Duration::from_millis(50));
        let slot = child.admit(&mut context)?;
        child
            .submit(Work::Pause(entered, wait), context, slot)
            .await
    });
    receive.await?;
    assert!(matches!(request.await?, Err(ObjectIoError::Timeout)));
    assert_eq!(io.metrics().depth, 1);
    assert_eq!(io.metrics().running, 1);
    assert!(matches!(
        io.create("query/a", b"bytes", context()).await,
        Err(ObjectIoError::Full)
    ));
    assert!(matches!(
        io.shutdown(OperationContext::new(Duration::from_millis(10)))
            .await,
        Err(ObjectIoError::Timeout)
    ));
    assert!(matches!(
        ObjectIo::open_small_local(
            &owner,
            LocalFileSystem::new_with_prefix(root.path())?,
            ObjectIoLimits::default(),
            context()
        )
        .await,
        Err(ObjectIoError::OwnerLocked)
    ));
    release.send(())?;
    io.shutdown(context()).await?;
    assert_eq!(io.metrics().depth, 0);
    assert_eq!(io.metrics().worker_capacity, 1);
    let next = ObjectIo::open_small_local(
        &owner,
        LocalFileSystem::new_with_prefix(root.path())?,
        ObjectIoLimits::default(),
        context(),
    )
    .await?;
    assert_eq!(
        next.small_owner_binding(),
        Some((owner.stream_id, owner.backend_id))
    );
    next.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn small_owner_binding_unknown_and_incomplete_controls_hold_startup() -> Result {
    let control = TempDir::new()?;
    let store = Arc::new(InMemory::new());
    let owner = SmallOwnerConfig {
        directory: control.path().to_path_buf(),
        stream_id: uuid::Uuid::new_v4(),
        backend_id: uuid::Uuid::new_v4(),
    };
    let io = ObjectIo::open_small_remote(
        &owner,
        store.clone(),
        tokio::runtime::Handle::current(),
        ObjectIoLimits::default(),
        context(),
    )
    .await?;
    assert_eq!(
        io.small_owner_binding(),
        Some((owner.stream_id, owner.backend_id))
    );
    io.shutdown(context()).await?;
    let mut other = owner.clone();
    other.backend_id = uuid::Uuid::new_v4();
    assert!(matches!(
        ObjectIo::open_small_remote(
            &other,
            store.clone(),
            tokio::runtime::Handle::current(),
            ObjectIoLimits::default(),
            context()
        )
        .await,
        Err(ObjectIoError::OwnerBinding)
    ));
    std::fs::write(control.path().join("unknown"), b"preserve")?;
    assert!(matches!(
        ObjectIo::open_small_remote(
            &owner,
            store.clone(),
            tokio::runtime::Handle::current(),
            ObjectIoLimits::default(),
            context()
        )
        .await,
        Err(ObjectIoError::Corrupt)
    ));
    assert_eq!(std::fs::read(control.path().join("unknown"))?, b"preserve");
    std::fs::remove_file(control.path().join("unknown"))?;
    std::fs::write(control.path().join("binding.tmp"), b"{incomplete")?;
    assert!(matches!(
        ObjectIo::open_small_remote(
            &owner,
            store.clone(),
            tokio::runtime::Handle::current(),
            ObjectIoLimits::default(),
            context()
        )
        .await,
        Err(ObjectIoError::Corrupt)
    ));
    assert_eq!(
        std::fs::read(control.path().join("binding.tmp"))?,
        b"{incomplete"
    );
    std::fs::remove_file(control.path().join("binding.tmp"))?;
    let io = ObjectIo::open_small_remote(
        &owner,
        store,
        tokio::runtime::Handle::current(),
        ObjectIoLimits::default(),
        context(),
    )
    .await?;
    io.shutdown(context()).await?;
    // The control lock is an empty owned file, not an arbitrary payload to sync.
    std::fs::write(control.path().join(".lock"), b"unexpected lock data")?;
    assert!(matches!(
        ObjectIo::open_small_remote(
            &owner,
            Arc::new(InMemory::new()),
            tokio::runtime::Handle::current(),
            ObjectIoLimits::default(),
            context()
        )
        .await,
        Err(ObjectIoError::Corrupt)
    ));
    assert_eq!(
        std::fs::read(control.path().join(".lock"))?,
        b"unexpected lock data"
    );
    Ok(())
}
