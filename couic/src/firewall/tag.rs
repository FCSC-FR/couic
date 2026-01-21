use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use common::RESERVED_TAG_NAME;

// IDs are monotonic and never reused
pub type TagId = u64;

#[derive(Debug, thiserror::Error)]
pub enum TagRegistryError {
    #[error("Tag registry lock poisoned")]
    LockPoisoned,
    #[error("Invalid Tag ID")]
    InvalidId,
    #[error("Tag table is full")]
    IdExhausted,
}

#[derive(Debug)]
struct TagEntry {
    name: Arc<str>,
    refcount: usize,
}

#[derive(Debug)]
struct TagRegistryInner {
    next_id: TagId,
    by_id: HashMap<TagId, TagEntry>,
    by_name: HashMap<Arc<str>, TagId>,
}

#[derive(Debug, Clone)]
pub struct TagRegistry {
    inner: Arc<RwLock<TagRegistryInner>>,
}

impl Default for TagRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TagRegistry {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(TagRegistryInner {
                next_id: 1,
                by_id: HashMap::new(),
                by_name: HashMap::new(),
            })),
        }
    }

    pub fn acquire(&self, tag: &str) -> Result<TagId, TagRegistryError> {
        let mut inner = self
            .inner
            .write()
            .map_err(|_| TagRegistryError::LockPoisoned)?;

        if let Some(&id) = inner.by_name.get(tag) {
            let Some(entry) = inner.by_id.get_mut(&id) else {
                return Err(TagRegistryError::InvalidId);
            };
            entry.refcount += 1;
            return Ok(id);
        }

        let id = inner.next_id;
        if id == u64::MAX {
            return Err(TagRegistryError::IdExhausted);
        }
        inner.next_id += 1;

        let name: Arc<str> = tag.into();
        inner.by_name.insert(Arc::clone(&name), id);
        inner.by_id.insert(id, TagEntry { name, refcount: 1 });

        Ok(id)
    }

    pub fn release(&self, id: TagId) -> Result<(), TagRegistryError> {
        let mut inner = self
            .inner
            .write()
            .map_err(|_| TagRegistryError::LockPoisoned)?;

        let should_remove = match inner.by_id.get_mut(&id) {
            Some(entry) => {
                debug_assert!(entry.refcount > 0, "refcount should never be zero in by_id");
                entry.refcount -= 1;
                entry.refcount == 0
            }
            None => return Ok(()),
        };

        if should_remove && let Some(entry) = inner.by_id.remove(&id) {
            inner.by_name.remove(&entry.name);
        }

        Ok(())
    }

    pub fn get_tag(&self, id: TagId) -> Result<Option<Arc<str>>, TagRegistryError> {
        let inner = self
            .inner
            .read()
            .map_err(|_| TagRegistryError::LockPoisoned)?;
        Ok(inner.by_id.get(&id).map(|e| Arc::clone(&e.name)))
    }

    pub fn get_tag_display(&self, id: TagId) -> Result<Option<String>, TagRegistryError> {
        let inner = self
            .inner
            .read()
            .map_err(|_| TagRegistryError::LockPoisoned)?;
        Ok(inner.by_id.get(&id).map(|e| {
            if e.name.is_empty() {
                RESERVED_TAG_NAME.into()
            } else {
                e.name.as_ref().into()
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_creates_new_tag() {
        let registry = TagRegistry::new();
        let id = registry.acquire("test").unwrap();
        assert_eq!(id, 1);
        assert_eq!(registry.get_tag(id).unwrap().unwrap().as_ref(), "test");
    }

    #[test]
    fn acquire_same_tag_returns_same_id() {
        let registry = TagRegistry::new();
        let id1 = registry.acquire("test").unwrap();
        let id2 = registry.acquire("test").unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn acquire_different_tags_returns_different_ids() {
        let registry = TagRegistry::new();
        let id1 = registry.acquire("foo").unwrap();
        let id2 = registry.acquire("bar").unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn release_decrements_refcount() {
        let registry = TagRegistry::new();
        let id = registry.acquire("test").unwrap();
        registry.acquire("test").unwrap(); // refcount = 2

        registry.release(id).unwrap();
        // Tag should still exist (refcount = 1)
        assert_eq!(registry.get_tag(id).unwrap().unwrap().as_ref(), "test");
    }

    #[test]
    fn release_removes_tag_when_refcount_zero() {
        let registry = TagRegistry::new();
        let id = registry.acquire("test").unwrap();

        registry.release(id).unwrap();
        // Tag should be removed
        assert!(registry.get_tag(id).unwrap().is_none());
    }

    #[test]
    fn release_nonexistent_id_is_noop() {
        let registry = TagRegistry::new();
        registry.release(999).unwrap(); // Should not panic or error
    }

    #[test]
    fn get_tag_nonexistent_returns_none() {
        let registry = TagRegistry::new();
        assert!(registry.get_tag(999).unwrap().is_none());
    }

    #[test]
    fn reacquire_after_release_gets_new_id() {
        let registry = TagRegistry::new();
        let id1 = registry.acquire("test").unwrap();
        registry.release(id1).unwrap();

        let id2 = registry.acquire("test").unwrap();
        assert_ne!(id1, id2); // New ID since tag was fully released
    }

    #[test]
    fn clone_shares_state() {
        let registry1 = TagRegistry::new();
        let registry2 = registry1.clone();

        let id = registry1.acquire("test").unwrap();
        assert_eq!(registry2.get_tag(id).unwrap().unwrap().as_ref(), "test");
    }

    #[test]
    fn empty_string_tag() {
        let registry = TagRegistry::new();
        let id = registry.acquire("").unwrap();
        assert_eq!(registry.get_tag(id).unwrap().unwrap().as_ref(), "");
    }

    #[test]
    fn thread_safe() {
        let registry = Arc::new(TagRegistry::new());
        let mut handles = vec![];
        let thread_count = 32;
        let iterations = 1000;
        let tag_names = vec!["test", "alpha", "beta", "gamma"];

        // Writer threads: acquire and release tags for multiple tag names
        for i in 0..(thread_count / 2) {
            let reg = registry.clone();
            let tag = tag_names[i % tag_names.len()].to_string();
            handles.push(std::thread::spawn(move || {
                for _ in 0..iterations {
                    let id = reg.acquire(&tag).unwrap();
                    assert!(reg.get_tag(id).unwrap().is_some());
                    reg.release(id).unwrap();
                }
            }));
        }

        // Reader threads: repeatedly read tags for multiple tag names
        for i in 0..(thread_count / 2) {
            let reg = registry.clone();
            let tag = tag_names[i % tag_names.len()].to_string();
            handles.push(std::thread::spawn(move || {
                for _ in 0..iterations {
                    // Try to read the tag by id (may not exist yet)
                    let id = reg.acquire(&tag).unwrap();
                    let _ = reg.get_tag(id);
                    reg.release(id).unwrap();
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // After all threads, all tags should be removed (refcount == 0)
        for tag in &tag_names {
            let id = registry.acquire(tag).unwrap();
            registry.release(id).unwrap();
            assert!(registry.get_tag(id).unwrap().is_none());
        }
    }
}
