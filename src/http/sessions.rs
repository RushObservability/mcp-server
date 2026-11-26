use futures_core::Stream;
use rmcp::{
    model::{ClientJsonRpcMessage, ServerJsonRpcMessage},
    transport::streamable_http_server::session::{
        ServerSseMessage, SessionId, SessionManager,
        local::{LocalSessionManager, LocalSessionManagerError},
    },
};
use tokio::sync::Mutex;

/// Bound the library's live session map. Serialize only creation so the limit
/// check and insert cannot race. Closing a session can always make progress.
pub(super) struct BoundedSessions {
    inner: LocalSessionManager,
    create_lock: Mutex<()>,
    limit: usize,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum SessionError {
    #[error("MCP session capacity reached")]
    Full,
    #[error(transparent)]
    Local(#[from] LocalSessionManagerError),
}

impl BoundedSessions {
    pub fn new(limit: usize) -> Self {
        Self {
            inner: LocalSessionManager::default(),
            create_lock: Mutex::new(()),
            limit,
        }
    }
}

impl SessionManager for BoundedSessions {
    type Error = SessionError;
    type Transport = <LocalSessionManager as SessionManager>::Transport;

    async fn create_session(&self) -> Result<(SessionId, Self::Transport), Self::Error> {
        let _creation = self.create_lock.lock().await;
        if self.inner.sessions.read().await.len() >= self.limit {
            return Err(SessionError::Full);
        }
        Ok(self.inner.create_session().await?)
    }

    async fn initialize_session(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<ServerJsonRpcMessage, Self::Error> {
        Ok(self.inner.initialize_session(id, message).await?)
    }

    async fn has_session(&self, id: &SessionId) -> Result<bool, Self::Error> {
        Ok(self.inner.has_session(id).await?)
    }

    async fn close_session(&self, id: &SessionId) -> Result<(), Self::Error> {
        Ok(self.inner.close_session(id).await?)
    }

    async fn create_stream(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        Ok(self.inner.create_stream(id, message).await?)
    }

    async fn accept_message(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<(), Self::Error> {
        Ok(self.inner.accept_message(id, message).await?)
    }

    async fn create_standalone_stream(
        &self,
        id: &SessionId,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        Ok(self.inner.create_standalone_stream(id).await?)
    }

    async fn resume(
        &self,
        id: &SessionId,
        last_event_id: String,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        Ok(self.inner.resume(id, last_event_id).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bounds_concurrent_creation_and_reuses_closed_capacity() {
        let sessions = BoundedSessions::new(1);
        let (left, right) = tokio::join!(sessions.create_session(), sessions.create_session());
        let (id, transport) = match (left, right) {
            (Ok(session), Err(SessionError::Full)) | (Err(SessionError::Full), Ok(session)) => {
                session
            }
            _ => panic!("expected exactly one admitted session"),
        };
        drop(transport);
        sessions.close_session(&id).await.unwrap();
        assert!(sessions.create_session().await.is_ok());
    }
}
