//! Real-time audio primitives.
//!
//! Queue overflow drops the oldest frame, preserving low latency instead of
//! allowing stale speech to accumulate.

use std::collections::VecDeque;

#[derive(Debug)]
pub struct FrameQueue<T> {
    frames: VecDeque<T>,
    capacity: usize,
    dropped_frames: u64,
}

impl<T> FrameQueue<T> {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "audio queue capacity must be non-zero");
        Self {
            frames: VecDeque::with_capacity(capacity),
            capacity,
            dropped_frames: 0,
        }
    }

    pub fn push_latest(&mut self, frame: T) {
        if self.frames.len() == self.capacity {
            self.frames.pop_front();
            self.dropped_frames += 1;
        }
        self.frames.push_back(frame);
    }

    pub fn pop(&mut self) -> Option<T> {
        self.frames.pop_front()
    }

    pub fn len(&self) -> usize {
        self.frames.len()
    }

    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    pub fn dropped_frames(&self) -> u64 {
        self.dropped_frames
    }
}

#[cfg(test)]
mod tests {
    use super::FrameQueue;

    #[test]
    fn overflow_discards_stale_frame() {
        let mut queue = FrameQueue::new(2);
        queue.push_latest(1);
        queue.push_latest(2);
        queue.push_latest(3);
        assert_eq!(queue.pop(), Some(2));
        assert_eq!(queue.pop(), Some(3));
        assert_eq!(queue.dropped_frames(), 1);
    }
}
