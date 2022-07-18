#![allow(dead_code)]
use futures::stream::{FuturesUnordered, Stream, StreamExt as _};
use std::future::Future;
use std::panic::resume_unwind;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinError};

#[derive(Debug)]
pub struct Nursery<T> {
    task_tx: mpsc::UnboundedSender<AbortOnDrop<T>>,
}

#[derive(Debug)]
pub struct NurseryStream<T> {
    task_rx: mpsc::UnboundedReceiver<AbortOnDrop<T>>,
    task_rx_closed: bool,
    futures: FuturesUnordered<AbortOnDrop<T>>,
}

#[derive(Debug)]
pub struct AbortOnDrop<T>(pub JoinHandle<T>);

impl<T> Nursery<T> {
    pub fn new() -> (Nursery<T>, NurseryStream<T>) {
        let (task_tx, task_rx) = mpsc::unbounded_channel();
        let nursery = Nursery { task_tx };
        let futures = FuturesUnordered::new();
        let stream = NurseryStream { task_rx, task_rx_closed: false, futures };
        (nursery, stream)
    }

    pub fn nurse(&self, task: JoinHandle<T>) {
        if self.task_tx.send(AbortOnDrop(task)).is_err() {
            panic!("the matching NurseryStream was dropped or aborted")
        }
    }
}

impl<T: Send + 'static> Nursery<T> {
    pub fn spawn<Fut>(&self, fut: Fut)
        where Fut: Future<Output = T> + Send + 'static
    {
        self.nurse(tokio::task::spawn(fut))
    }
}

impl<T> NurseryStream<T> {
    pub fn abort(&mut self) {
        self.task_rx.close();
        self.futures.clear();
    }
}

impl<T> Stream for NurseryStream<T> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        let stream = self.get_mut();

        while !stream.task_rx_closed {
            match stream.task_rx.poll_recv(cx) {
                Poll::Ready(Some(task)) => stream.futures.push(task),
                Poll::Ready(None) => stream.task_rx_closed = true,
                Poll::Pending => break,
            }
        }

        loop {
            return match Pin::new(&mut stream.futures).poll_next(cx) {
                Poll::Ready(Some(Ok(res))) =>
                    Poll::Ready(Some(res)),
                Poll::Ready(Some(Err(join_err))) =>
                    if join_err.is_cancelled() {
                        continue
                    } else if join_err.is_panic() {
                        resume_unwind(join_err.into_panic())
                    } else {
                        panic!("task failed with unknown error: {}", join_err)
                    },
                Poll::Ready(None) =>
                    if stream.task_rx_closed {
                        Poll::Ready(None) 
                    } else {
                        Poll::Pending
                    },
                Poll::Pending =>
                    Poll::Pending,
            }
        }
    }
}

impl NurseryStream<()> {
    /*
    pub async fn run(&mut self) {
        while let Some(()) = self.next().await {}
    }
    */
}

impl<E> NurseryStream<Result<(), E>> {
    pub async fn try_run(&mut self) -> Result<(), E> {
        loop {
            match self.next().await {
                Some(Ok(())) => continue,
                Some(Err(err)) => return Err(err),
                None => return Ok(()),
            }
        }
    }
}

impl<T> Future for AbortOnDrop<T> {
    type Output = std::result::Result<T, JoinError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.get_mut().0).poll(cx)
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl<T> Clone for Nursery<T> {
    fn clone(&self) -> Self {
        Nursery { task_tx: self.task_tx.clone() }
    }
}
