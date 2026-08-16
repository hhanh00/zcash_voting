//! Small async transport abstraction for vote commitment tree sync.

use std::{future::Future, pin::Pin};

/// Response returned by a tree-sync transport request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Errors returned by a concrete tree-sync transport implementation.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TransportError {
    #[error("request failed: {0}")]
    Request(String),
}

/// A pinned boxed future returned by [`Transport::get`].
pub type TransportFuture<'a> =
    Pin<Box<dyn Future<Output = Result<TransportResponse, TransportError>> + Send + 'a>>;

/// Async GET-only transport used by [`crate::http_sync_api::HttpTreeSyncApi`].
pub trait Transport: Send + Sync {
    fn get<'a>(&'a self, url: &'a str) -> TransportFuture<'a>;
}
