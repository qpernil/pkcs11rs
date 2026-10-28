//! FIFO admission for one wire phase, released before target computation.
use crate::registry::TransportError;
use std::{
    collections::VecDeque,
    sync::{Arc, Condvar, Mutex},
    time::Instant,
};

#[derive(Default)]
pub(super) struct FairQueue {
    turns: Mutex<VecDeque<Arc<()>>>,
    changed: Condvar,
}

pub(super) struct Turn {
    queue: Arc<FairQueue>,
    token: Arc<()>,
}

impl FairQueue {
    pub(super) fn acquire(self: &Arc<Self>, deadline: Instant) -> Result<Turn, TransportError> {
        self.enqueue().wait(deadline)
    }

    fn enqueue(self: &Arc<Self>) -> Turn {
        let turn = Turn {
            queue: self.clone(),
            token: Arc::new(()),
        };
        self.turns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push_back(turn.token.clone());
        turn
    }
}

impl Turn {
    fn wait(self, deadline: Instant) -> Result<Self, TransportError> {
        let mut turns = self.queue.turns.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            let now = Instant::now();
            if now >= deadline {
                // Drop the mutex before the RAII turn removes its queue entry.
                drop(turns);
                return Err(TransportError::device(
                    "timed out waiting for exclusive I2C bus access",
                ));
            }
            if turns
                .front()
                .is_some_and(|front| Arc::ptr_eq(front, &self.token))
            {
                drop(turns);
                return Ok(self);
            }
            (turns, _) = self
                .queue
                .changed
                .wait_timeout(turns, deadline - now)
                .unwrap_or_else(|e| e.into_inner());
        }
    }
}

impl Drop for Turn {
    fn drop(&mut self) {
        let mut turns = self.queue.turns.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(index) = turns
            .iter()
            .position(|token| Arc::ptr_eq(token, &self.token))
        {
            turns.remove(index);
        }
        self.queue.changed.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::mpsc, thread, time::Duration};

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    #[test]
    fn queued_peer_precedes_a_hot_workers_reacquisition() {
        let queue = Arc::new(FairQueue::default());
        let held = queue.acquire(deadline()).unwrap();
        let peer = queue.enqueue();
        let reacquire = queue.enqueue();
        let (acquired, received) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        let worker = thread::spawn(move || {
            let turn = peer.wait(deadline()).unwrap();
            acquired.send(()).unwrap();
            wait.recv_timeout(Duration::from_secs(5)).unwrap();
            drop(turn);
        });
        drop(held);
        received.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(
            reacquire
                .wait(Instant::now() + Duration::from_millis(10))
                .is_err(),
            "reacquisition must not bypass an earlier peer"
        );
        release.send(()).unwrap();
        worker.join().unwrap();
        assert!(queue.acquire(deadline()).is_ok());
    }

    #[test]
    fn expired_middle_waiter_does_not_block_its_successor() {
        let queue = Arc::new(FairQueue::default());
        let held = queue.acquire(deadline()).unwrap();
        let expired = queue.enqueue();
        let successor = queue.enqueue();
        assert!(expired.wait(Instant::now()).is_err());
        drop(held);
        assert!(successor.wait(deadline()).is_ok());
        assert!(queue.acquire(deadline()).is_ok());
    }

    #[test]
    fn expired_head_cannot_acquire_a_free_bus() {
        let queue = Arc::new(FairQueue::default());
        assert!(queue.acquire(Instant::now()).is_err());
        assert!(queue.acquire(deadline()).is_ok());
    }

    #[test]
    fn independent_adapters_do_not_share_a_queue() {
        let first = Arc::new(FairQueue::default());
        let second = Arc::new(FairQueue::default());
        let _held = first.acquire(deadline()).unwrap();
        assert!(second.acquire(deadline()).is_ok());
    }
}
