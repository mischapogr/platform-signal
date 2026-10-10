//! Owned write-once version emulation; no AWS/versioning qualification.
use object_store::{ObjectStore, memory::InMemory};
#[derive(Debug)]
pub struct Versions(pub InMemory);
impl std::fmt::Display for Versions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("owned immutable single-version fixture")
    }
}
fn unused() -> object_store::Error {
    object_store::Error::NotImplemented {
        operation: "unused fixture operation".into(),
        implementer: "Versions".into(),
    }
}
#[async_trait::async_trait]
impl ObjectStore for Versions {
    async fn put_opts(
        &self,
        p: &object_store::path::Path,
        b: object_store::PutPayload,
        o: object_store::PutOptions,
    ) -> object_store::Result<object_store::PutResult> {
        if !matches!(o.mode, object_store::PutMode::Create) {
            return Err(unused());
        }
        let mut result = self.0.put_opts(p, b, o).await?;
        result.version = Some("owned-v1".into());
        Ok(result)
    }
    async fn get_opts(
        &self,
        p: &object_store::path::Path,
        mut o: object_store::GetOptions,
    ) -> object_store::Result<object_store::GetResult> {
        if o.version.as_deref().is_some_and(|v| v != "owned-v1") {
            return Err(object_store::Error::NotFound {
                path: p.to_string(),
                source: std::io::Error::other("unavailable fixture version").into(),
            });
        }
        o.version = None;
        let mut result = self.0.get_opts(p, o).await?;
        result.meta.version = Some("owned-v1".into());
        Ok(result)
    }
    async fn put_multipart_opts(
        &self,
        _: &object_store::path::Path,
        _: object_store::PutMultipartOptions,
    ) -> object_store::Result<Box<dyn object_store::MultipartUpload>> {
        Err(unused())
    }
    fn list(
        &self,
        p: Option<&object_store::path::Path>,
    ) -> futures_util::stream::BoxStream<'static, object_store::Result<object_store::ObjectMeta>>
    {
        self.0.list(p)
    }
    fn delete_stream(
        &self,
        _: futures_util::stream::BoxStream<'static, object_store::Result<object_store::path::Path>>,
    ) -> futures_util::stream::BoxStream<'static, object_store::Result<object_store::path::Path>>
    {
        Box::pin(futures_util::stream::once(async { Err(unused()) }))
    }
    async fn list_with_delimiter(
        &self,
        _: Option<&object_store::path::Path>,
    ) -> object_store::Result<object_store::ListResult> {
        Err(unused())
    }
    async fn copy_opts(
        &self,
        _: &object_store::path::Path,
        _: &object_store::path::Path,
        _: object_store::CopyOptions,
    ) -> object_store::Result<()> {
        Err(unused())
    }
}
