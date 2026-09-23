// Keep an inner resource alive only while its outer resource exists, and
// release the inner one first even when the outer resource is reference-counted.
pub(crate) struct NestedSession<Inner, Outer> {
    pub(crate) inner: Option<Inner>,
    pub(crate) outer: Option<Outer>,
}

impl<Inner, Outer> Drop for NestedSession<Inner, Outer> {
    fn drop(&mut self) {
        self.inner.take();
    }
}

#[cfg(test)]
mod tests {
    use super::NestedSession;
    use std::sync::{Arc, Mutex};

    struct DropProbe {
        name: &'static str,
        order: Arc<Mutex<Vec<&'static str>>>,
    }

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.order.lock().unwrap().push(self.name);
        }
    }

    #[test]
    fn inner_session_ends_before_outer_lease() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let outer = Arc::new(DropProbe {
            name: "NFC slot",
            order: order.clone(),
        });
        let session = NestedSession {
            inner: Some(DropProbe {
                name: "card session",
                order: order.clone(),
            }),
            outer: Some(outer.clone()),
        };
        assert!(session.outer.is_some());

        // The transport can relinquish the NFC slot first. The worker's lease
        // still keeps it alive until the card session has ended.
        drop(outer);
        assert!(order.lock().unwrap().is_empty());
        drop(session);
        assert_eq!(*order.lock().unwrap(), ["card session", "NFC slot"]);
    }
}
