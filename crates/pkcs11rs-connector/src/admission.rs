//! Reserve capacity in MakeService, before axum-server spawns a connection task.
//! The acceptor transfers connection ownership to the IO stream and releases the
//! separate handshake reservation as soon as TLS acceptance completes.
use axum::Router;
use axum_server::accept::Accept;
use futures_util::{FutureExt, future::BoxFuture};
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{OwnedSemaphorePermit, Semaphore, watch},
};
use tower::Service;

#[derive(Clone)]
pub struct Admission {
    app: Router,
    connections: Arc<Semaphore>,
    handshakes: Option<Arc<Semaphore>>,
    shutdown: watch::Sender<()>,
}

impl Admission {
    pub fn new(app: Router, max_connections: usize, max_handshakes: Option<usize>) -> Self {
        Self {
            app,
            connections: Arc::new(Semaphore::new(max_connections)),
            handshakes: max_handshakes.map(|limit| Arc::new(Semaphore::new(limit))),
            shutdown: watch::channel(()).0,
        }
    }

    pub fn acceptor<A>(&self, inner: A) -> AdmissionAcceptor<A> {
        AdmissionAcceptor {
            inner,
            shutdown: self.shutdown.subscribe(),
        }
    }

    pub fn admit(&self) -> io::Result<Admitted<Router>> {
        let connection = self.connections.clone().try_acquire_owned().map_err(|_| {
            tracing::debug!("rejecting connection: open connection limit reached");
            io::Error::from(io::ErrorKind::WouldBlock)
        })?;
        let handshake = self
            .handshakes
            .as_ref()
            .map(|limit| {
                limit
                    .clone()
                    .try_acquire_owned()
                    .map(Arc::new)
                    .map_err(|_| {
                        tracing::debug!("rejecting connection: TLS handshake limit reached");
                        io::Error::from(io::ErrorKind::WouldBlock)
                    })
            })
            .transpose()?;
        Ok(Admitted {
            inner: self.app.clone(),
            connection: Arc::new(connection),
            handshake,
        })
    }
}

// Wraps the service before acceptance, then the IO stream for its full lifetime.
#[derive(Clone)]
pub struct Admitted<S> {
    inner: S,
    connection: Arc<OwnedSemaphorePermit>,
    handshake: Option<Arc<OwnedSemaphorePermit>>,
}

impl<S, R> Service<R> for Admitted<S>
where
    S: Service<R>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: R) -> Self::Future {
        self.inner.call(request)
    }
}

#[derive(Clone)]
pub struct AdmissionAcceptor<A> {
    inner: A,
    shutdown: watch::Receiver<()>,
}

impl<A, I, S> Accept<I, Admitted<S>> for AdmissionAcceptor<A>
where
    A: Accept<I, S>,
    A::Future: Send + 'static,
    A::Stream: Send + 'static,
    A::Service: Send + 'static,
{
    type Stream = Admitted<A::Stream>;
    type Service = A::Service;
    type Future = BoxFuture<'static, io::Result<(Self::Stream, Self::Service)>>;

    fn accept(&self, stream: I, service: Admitted<S>) -> Self::Future {
        let Admitted {
            inner,
            connection,
            handshake,
        } = service;
        let accepted = self.inner.accept(stream, inner);
        let mut shutdown = self.shutdown.clone();
        async move {
            // Dropping the server's MakeService cancels pre-HTTP acceptance too.
            // axum-server's own shutdown watcher starts after Accept completes.
            let (stream, service) = tokio::select! {
                biased;
                _ = shutdown.changed() => return Err(io::ErrorKind::Interrupted.into()),
                result = accepted => result?,
            };
            drop(handshake);
            Ok((
                Admitted {
                    inner: stream,
                    connection,
                    handshake: None,
                },
                service,
            ))
        }
        .boxed()
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for Admitted<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for Admitted<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buffer)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum_server::accept::DefaultAcceptor;

    #[tokio::test]
    async fn capacity_is_reserved_before_the_connection_future_is_polled() {
        let admission = Admission::new(Router::new(), 1, Some(1));
        let connections = admission.connections.clone();
        let handshakes = admission.handshakes.clone().unwrap();
        let mut make_service =
            tower::service_fn(move |_: std::net::SocketAddr| std::future::ready(admission.admit()));
        let peer = "127.0.0.1:1".parse().unwrap();
        let pending = make_service.call(peer);
        assert_eq!(connections.available_permits(), 0);
        assert_eq!(handshakes.available_permits(), 0);
        assert!(make_service.call(peer).await.is_err());
        drop(pending);
        assert!(make_service.call(peer).await.is_ok());
    }

    #[tokio::test]
    async fn rejected_handshakes_do_not_leak_connection_capacity() {
        let admission = Admission::new(Router::new(), 2, Some(1));
        let first = admission.admit().unwrap();
        for _ in 0..100 {
            assert!(admission.admit().is_err());
            assert_eq!(admission.connections.available_permits(), 1);
        }
        drop(first);
        assert_eq!(admission.connections.available_permits(), 2);
        assert_eq!(
            admission.handshakes.as_ref().unwrap().available_permits(),
            1
        );
    }

    #[tokio::test]
    async fn successful_accept_releases_handshake_but_holds_connection_until_io_drop() {
        let admission = Admission::new(Router::new(), 2, Some(1));
        let acceptor = admission.acceptor(DefaultAcceptor::new());
        let (io, _peer) = tokio::io::duplex(8);
        let (stream, service) = acceptor
            .accept(io, admission.admit().unwrap())
            .await
            .unwrap();
        drop(service);
        assert_eq!(admission.connections.available_permits(), 1);
        assert_eq!(
            admission.handshakes.as_ref().unwrap().available_permits(),
            1
        );
        drop(stream);
        assert_eq!(admission.connections.available_permits(), 2);
    }

    #[derive(Clone)]
    struct PendingAcceptor;

    impl<I: Send + 'static, S: Send + 'static> Accept<I, S> for PendingAcceptor {
        type Stream = I;
        type Service = S;
        type Future = BoxFuture<'static, io::Result<(I, S)>>;

        fn accept(&self, stream: I, service: S) -> Self::Future {
            Box::pin(async move {
                std::future::pending::<()>().await;
                Ok((stream, service))
            })
        }
    }

    #[tokio::test]
    async fn cancelling_accept_releases_both_reservations() {
        let admission = Admission::new(Router::new(), 1, Some(1));
        let acceptor = admission.acceptor(PendingAcceptor);
        let (io, _peer) = tokio::io::duplex(8);
        let mut future = acceptor.accept(io, admission.admit().unwrap());
        assert!(futures_util::poll!(future.as_mut()).is_pending());
        drop(future);
        assert!(admission.admit().is_ok());
    }

    #[tokio::test]
    async fn server_drop_cancels_an_incomplete_accept() {
        let admission = Admission::new(Router::new(), 1, Some(1));
        let acceptor = admission.acceptor(PendingAcceptor);
        let connections = admission.connections.clone();
        let handshakes = admission.handshakes.clone().unwrap();
        let (io, _peer) = tokio::io::duplex(8);
        let mut future = acceptor.accept(io, admission.admit().unwrap());
        assert!(futures_util::poll!(future.as_mut()).is_pending());
        drop(admission);
        assert_eq!(
            future.await.err().unwrap().kind(),
            io::ErrorKind::Interrupted
        );
        assert_eq!(connections.available_permits(), 1);
        assert_eq!(handshakes.available_permits(), 1);
    }
}
