use std::sync::{
    mpsc::{self, Receiver, SyncSender},
    Arc, Mutex,
};

use cpal::{
    traits::{DeviceTrait, HostTrait, StreamTrait},
    FromSample, Sample, SampleFormat, SizedSample, Stream, StreamConfig,
};
use incomudon_audio::{CaptureFrameAssembler, PlaybackBuffer, PCM_SAMPLE_RATE};

const CAPTURE_QUEUE_CAPACITY: usize = 8;
const PLAYBACK_QUEUE_FRAMES: usize = 12;

pub struct DesktopAudio {
    capture_frames: Receiver<Vec<u8>>,
    playback: Arc<Mutex<PlaybackBuffer>>,
    _input_stream: Stream,
    _output_stream: Stream,
}

impl DesktopAudio {
    pub fn open() -> Result<Self, String> {
        let host = cpal::default_host();
        let input = host
            .default_input_device()
            .ok_or_else(|| "no default microphone is available".to_owned())?;
        let output = host
            .default_output_device()
            .ok_or_else(|| "no default speaker is available".to_owned())?;
        let input_config = input
            .default_input_config()
            .map_err(|error| error.to_string())?;
        let output_config = output
            .default_output_config()
            .map_err(|error| error.to_string())?;
        let (capture_tx, capture_frames) = mpsc::sync_channel(CAPTURE_QUEUE_CAPACITY);
        let playback = Arc::new(Mutex::new(PlaybackBuffer::new(PLAYBACK_QUEUE_FRAMES)));

        let input_stream = build_input_stream(&input, &input_config, capture_tx)?;
        let output_stream = build_output_stream(&output, &output_config, Arc::clone(&playback))?;
        input_stream.play().map_err(|error| error.to_string())?;
        output_stream.play().map_err(|error| error.to_string())?;

        Ok(Self {
            capture_frames,
            playback,
            _input_stream: input_stream,
            _output_stream: output_stream,
        })
    }

    pub fn try_next_capture_frame(&self) -> Option<Vec<u8>> {
        self.capture_frames.try_recv().ok()
    }

    /// Drops stale microphone frames collected while PTT was inactive.
    pub fn discard_capture_frames(&self) {
        while self.capture_frames.try_recv().is_ok() {}
    }

    pub fn queue_playback_frame(&self, frame: &[u8]) -> bool {
        self.playback
            .lock()
            .expect("playback buffer lock poisoned")
            .push_pcm_frame(frame)
    }
}

fn build_input_stream(
    device: &cpal::Device,
    supported_config: &cpal::SupportedStreamConfig,
    sender: SyncSender<Vec<u8>>,
) -> Result<Stream, String> {
    let stream_config: StreamConfig = supported_config.clone().into();
    let assembler = Arc::new(Mutex::new(CaptureFrameAssembler::new(
        stream_config.sample_rate.0,
        stream_config.channels as usize,
    )));
    match supported_config.sample_format() {
        SampleFormat::F32 => input_stream::<f32>(device, &stream_config, sender, assembler),
        SampleFormat::I16 => input_stream::<i16>(device, &stream_config, sender, assembler),
        SampleFormat::U16 => input_stream::<u16>(device, &stream_config, sender, assembler),
        format => Err(format!("unsupported microphone sample format: {format:?}")),
    }
}

fn input_stream<T>(
    device: &cpal::Device,
    config: &StreamConfig,
    sender: SyncSender<Vec<u8>>,
    assembler: Arc<Mutex<CaptureFrameAssembler>>,
) -> Result<Stream, String>
where
    T: Sample + SizedSample,
    f32: FromSample<T>,
{
    device
        .build_input_stream(
            config,
            move |data: &[T], _| {
                let samples: Vec<f32> = data
                    .iter()
                    .map(|sample| sample.to_sample::<f32>())
                    .collect();
                let Ok(mut assembler) = assembler.lock() else {
                    return;
                };
                for frame in assembler.push_interleaved_f32(&samples) {
                    let _ = sender.try_send(frame);
                }
            },
            |_| {},
            None,
        )
        .map_err(|error| error.to_string())
}

fn build_output_stream(
    device: &cpal::Device,
    supported_config: &cpal::SupportedStreamConfig,
    playback: Arc<Mutex<PlaybackBuffer>>,
) -> Result<Stream, String> {
    let stream_config: StreamConfig = supported_config.clone().into();
    match supported_config.sample_format() {
        SampleFormat::F32 => output_stream::<f32>(device, &stream_config, playback),
        SampleFormat::I16 => output_stream::<i16>(device, &stream_config, playback),
        SampleFormat::U16 => output_stream::<u16>(device, &stream_config, playback),
        format => Err(format!("unsupported speaker sample format: {format:?}")),
    }
}

fn output_stream<T>(
    device: &cpal::Device,
    config: &StreamConfig,
    playback: Arc<Mutex<PlaybackBuffer>>,
) -> Result<Stream, String>
where
    T: Sample + FromSample<f32> + SizedSample,
{
    let channels = config.channels as usize;
    let output_rate = config.sample_rate.0;
    let mut phase = 0_u32;
    let mut current_sample = 0.0_f32;
    device
        .build_output_stream(
            config,
            move |data: &mut [T], _| {
                let Ok(mut playback) = playback.lock() else {
                    data.fill(T::from_sample(0.0));
                    return;
                };
                for device_frame in data.chunks_exact_mut(channels) {
                    phase = phase.saturating_add(PCM_SAMPLE_RATE);
                    if phase >= output_rate {
                        phase -= output_rate;
                        current_sample = playback
                            .pop_sample()
                            .map(|sample| sample as f32 / i16::MAX as f32)
                            .unwrap_or(0.0);
                    }
                    let output_sample = T::from_sample(current_sample);
                    device_frame.fill(output_sample);
                }
            },
            |_| {},
            None,
        )
        .map_err(|error| error.to_string())
}
