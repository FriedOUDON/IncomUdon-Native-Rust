//! Real-time audio primitives.
//!
//! Queue overflow drops the oldest frame, preserving low latency instead of
//! allowing stale speech to accumulate.

use std::collections::VecDeque;

pub const PCM_SAMPLE_RATE: u32 = 8_000;
pub const PCM_FRAME_SAMPLES: usize = 160;
pub const PCM_FRAME_BYTES: usize = PCM_FRAME_SAMPLES * 2;

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

/// Converts interleaved device samples into 20 ms mono PCM frames at 8 kHz.
///
/// The first PCM milestone uses deterministic sample-rate conversion without
/// buffering more than one frame. A higher quality resampler can later replace
/// this component without changing the Relay packet layer.
#[derive(Debug)]
pub struct CaptureFrameAssembler {
    input_rate: u32,
    channels: usize,
    phase: u32,
    frame: Vec<i16>,
}

impl CaptureFrameAssembler {
    pub fn new(input_rate: u32, channels: usize) -> Self {
        assert!(input_rate > 0, "input sample rate must be non-zero");
        assert!(channels > 0, "input channels must be non-zero");
        Self {
            input_rate,
            channels,
            phase: 0,
            frame: Vec::with_capacity(PCM_FRAME_SAMPLES),
        }
    }

    pub fn push_interleaved_f32(&mut self, samples: &[f32]) -> Vec<Vec<u8>> {
        let mut complete_frames = Vec::new();
        for device_frame in samples.chunks_exact(self.channels) {
            let mono = device_frame.iter().copied().sum::<f32>() / self.channels as f32;
            self.phase = self.phase.saturating_add(PCM_SAMPLE_RATE);
            if self.phase < self.input_rate {
                continue;
            }
            self.phase -= self.input_rate;
            self.frame.push(float_to_i16(mono));
            if self.frame.len() == PCM_FRAME_SAMPLES {
                complete_frames.push(encode_pcm_frame(&self.frame));
                self.frame.clear();
            }
        }
        complete_frames
    }
}

/// Bounded PCM playback buffer. On overflow, old samples are removed so the
/// output catches up instead of accumulating seconds of stale speech.
#[derive(Debug)]
pub struct PlaybackBuffer {
    samples: VecDeque<i16>,
    capacity_samples: usize,
    dropped_samples: u64,
}

impl PlaybackBuffer {
    pub fn new(frame_capacity: usize) -> Self {
        assert!(frame_capacity > 0, "playback capacity must be non-zero");
        Self {
            samples: VecDeque::with_capacity(frame_capacity * PCM_FRAME_SAMPLES),
            capacity_samples: frame_capacity * PCM_FRAME_SAMPLES,
            dropped_samples: 0,
        }
    }

    pub fn push_pcm_frame(&mut self, frame: &[u8]) -> bool {
        let Some(samples) = decode_pcm_frame(frame) else {
            return false;
        };
        let overflow = self
            .samples
            .len()
            .saturating_add(samples.len())
            .saturating_sub(self.capacity_samples);
        for _ in 0..overflow {
            self.samples.pop_front();
        }
        self.dropped_samples += overflow as u64;
        self.samples.extend(samples);
        true
    }

    pub fn pop_sample(&mut self) -> Option<i16> {
        self.samples.pop_front()
    }

    pub fn len_samples(&self) -> usize {
        self.samples.len()
    }

    pub fn dropped_samples(&self) -> u64 {
        self.dropped_samples
    }
}

pub fn encode_pcm_frame(samples: &[i16]) -> Vec<u8> {
    assert_eq!(
        samples.len(),
        PCM_FRAME_SAMPLES,
        "PCM frame must be exactly 20 ms"
    );
    let mut bytes = Vec::with_capacity(PCM_FRAME_BYTES);
    for sample in samples {
        bytes.extend_from_slice(&sample.to_le_bytes());
    }
    bytes
}

pub fn decode_pcm_frame(bytes: &[u8]) -> Option<Vec<i16>> {
    if bytes.len() != PCM_FRAME_BYTES {
        return None;
    }
    Some(
        bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|sample| i16::from_le_bytes(*sample))
            .collect(),
    )
}

fn float_to_i16(sample: f32) -> i16 {
    (sample.clamp(-1.0, 1.0) * i16::MAX as f32).round() as i16
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn pcm_frame_round_trip_is_little_endian() {
        let mut samples = vec![0_i16; PCM_FRAME_SAMPLES];
        samples[0] = -123;
        samples[1] = 456;
        assert_eq!(
            decode_pcm_frame(&encode_pcm_frame(&samples)).unwrap(),
            samples
        );
    }

    #[test]
    fn capture_assembler_emits_twenty_millisecond_frames() {
        let mut assembler = CaptureFrameAssembler::new(48_000, 1);
        let frames = assembler.push_interleaved_f32(&vec![0.5; 48_000 / 50]);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].len(), PCM_FRAME_BYTES);
    }

    #[test]
    fn playback_overflow_discards_oldest_samples() {
        let mut playback = PlaybackBuffer::new(1);
        let frame = encode_pcm_frame(&vec![1; PCM_FRAME_SAMPLES]);
        assert!(playback.push_pcm_frame(&frame));
        assert!(playback.push_pcm_frame(&frame));
        assert_eq!(playback.len_samples(), PCM_FRAME_SAMPLES);
        assert_eq!(playback.dropped_samples(), PCM_FRAME_SAMPLES as u64);
    }
}
