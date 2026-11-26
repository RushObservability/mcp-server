use std::collections::HashMap;

use futures_core::Stream;
use rmcp::{
    model::{ClientJsonRpcMessage, ServerJsonRpcMessage},
    transport::streamable_http_server::session::{
        ServerSseMessage, SessionId, SessionManager,
        local::{LocalSessionManager, LocalSessionManagerError},
    },
};
use tokio::sync::Mutex;

tokio::task_local! {
    /// The credential hash of the HTTP request being handled, set by the auth layer.
    pub(super) static OWNER: u64;
}

/// Bound the library's live session map, overall and per credential, and
/// remember which credential opened each session. Serialize only creation so
/// the limit check and insert cannot race. Closing a session can always make
/// progress.
pub(super) struct BoundedSessions {
    inner: LocalSessionManager,
    create_lock: Mutex<()>,
    limit: usize,
    per_owner: usize,
    owners: std::sync::Mutex<HashMap<SessionId, u64>>,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum SessionError {
    #[error("MCP session capacity reached")]
    Full,
    #[error("MCP session capacity for this key reached")]
    OwnerFull,
    #[error(transparent)]
    Local(#[from] LocalSessionManagerError),
}

impl BoundedSessions {
    pub fn new(limit: usize, per_owner: usize) -> Self {
        Self {
            inner: LocalSessionManager::default(),
            create_lock: Mutex::new(()),
            limit,
            per_owner,
            owners: std::sync::Mutex::new(HashMap::new()),
        }
    }

    fn owners(&self) -> std::sync::MutexGuard<'_, HashMap<SessionId, u64>> {
        self.owners.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The credential hash that opened session `id`, if it is live.
    pub fn owner_of(&self, id: &str) -> Option<u64> {
        self.owners().get(id).copied()
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
        let owner = OWNER.try_with(|o| *o).ok();
        if let Some(owner) = owner {
            if self.owners().values().filter(|o| **o == owner).count() >= self.per_owner {
                return Err(SessionError::OwnerFull);
            }
        }
        let (id, transport) = self.inner.create_session().await?;
        if let Some(owner) = owner {
            self.owners().insert(id.clone(), owner);
        }
        Ok((id, transport))
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
        self.owners().remove(id);
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
        let sessions = BoundedSessions::new(1, 1);
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

    #[tokio::test]
    async fn each_owner_gets_its_own_share_of_sessions() {
        let sessions = BoundedSessions::new(3, 1);
        let (mine, _t1) = OWNER.scope(1, sessions.create_session()).await.unwrap();
        assert!(matches!(
            OWNER.scope(1, sessions.create_session()).await,
            Err(SessionError::OwnerFull)
        ));
        let (theirs, _t2) = OWNER.scope(2, sessions.create_session()).await.unwrap();
        assert_eq!(sessions.owner_of(&mine), Some(1));
        assert_eq!(sessions.owner_of(&theirs), Some(2));

        sessions.close_session(&mine).await.unwrap();
        assert_eq!(sessions.owner_of(&mine), None);
        assert!(OWNER.scope(1, sessions.create_session()).await.is_ok());
    }
}
