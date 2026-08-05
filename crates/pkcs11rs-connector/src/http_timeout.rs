use axum_server::accept::Accept;
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{sleep, Sleep},
};

#[derive(Clone, Debug)]
pub struct WriteTimeoutAcceptor<A> {
    inner: A,
    timeout: Duration,
}

impl<A> WriteTimeoutAcceptor<A> {
    pub fn new(inner: A, timeout: Duration) -> Self {
        Self { inner, timeout }
    }
}

impl<A, I, S> Accept<I, S> for WriteTimeoutAcceptor<A>
where
    A: Accept<I, S>,
    A::Future: Send + 'static,
    A::Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    A::Service: Send + 'static,
{
    type Stream = WriteTimeoutStream<A::Stream>;
    type Service = A::Service;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let accepted = self.inner.accept(stream, service);
        let timeout = self.timeout;
        Box::pin(async move {
            let (stream, service) = accepted.await?;
            Ok((WriteTimeoutStream::new(stream, timeout), service))
        })
    }
}

#[derive(Debug)]
pub struct WriteTimeoutStream<I> {
    inner: I,
    timeout: Duration,
    write_sleep: Option<Pin<Box<Sleep>>>,
}

impl<I> WriteTimeoutStream<I> {
    fn new(inner: I, timeout: Duration) -> Self {
        Self {
            inner,
            timeout,
            write_sleep: None,
        }
    }

    fn pending_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let timeout = self.timeout;
        let sleep = self
            .write_sleep
            .get_or_insert_with(|| Box::pin(sleep(timeout)));
        match sleep.as_mut().poll(cx) {
            Poll::Ready(()) => {
                self.write_sleep = None;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "HTTP response write timed out",
                )))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn write_completed<T>(&mut self, result: Poll<io::Result<T>>) -> Poll<io::Result<T>> {
        if result.is_ready() {
            self.write_sleep = None;
        }
        result
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for WriteTimeoutStream<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for WriteTimeoutStream<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buffer);
        match result {
            Poll::Pending => self.pending_write(cx).map(|result| result.map(|()| 0)),
            ready => self.write_completed(ready),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_flush(cx);
        match result {
            Poll::Pending => self.pending_write(cx),
            ready => self.write_completed(ready),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_shutdown(cx);
        match result {
            Poll::Pending => self.pending_write(cx),
            ready => self.write_completed(ready),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn response_write_times_out_only_after_write_blocks() {
        let (stream, _peer) = tokio::io::duplex(1);
        let mut stream = WriteTimeoutStream::new(stream, Duration::from_millis(20));

        tokio::time::sleep(Duration::from_millis(40)).await;
        stream.write_all(b"a").await.unwrap();
        let error = stream.write_all(b"b").await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
}
