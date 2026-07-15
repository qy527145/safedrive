use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;

const RATE_WINDOW: Duration = Duration::from_millis(1500);
const MIN_SAMPLE_WINDOW_SECS: f64 = 0.35;

#[derive(Clone, Copy)]
enum Direction {
    Upload,
    Download,
}

struct Event {
    at: Instant,
    bytes: u64,
    direction: Direction,
    file: Option<String>,
}

#[derive(Default)]
pub struct TransferTracker {
    events: Mutex<VecDeque<Event>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferSnapshot {
    pub upload_speed: u64,
    pub download_speed: u64,
    pub file_download_speeds: HashMap<String, u64>,
}

impl TransferTracker {
    pub fn upload(&self, bytes: u64) {
        self.record(bytes, Direction::Upload, None);
    }
    pub fn download(&self, file: String, bytes: u64) {
        self.record(bytes, Direction::Download, Some(file));
    }
    fn record(&self, bytes: u64, direction: Direction, file: Option<String>) {
        if bytes == 0 {
            return;
        }
        let mut events = self.events.lock().unwrap();
        let now = Instant::now();
        events.push_back(Event {
            at: now,
            bytes,
            direction,
            file,
        });
        while events
            .front()
            .is_some_and(|e| now.duration_since(e.at) > RATE_WINDOW)
        {
            events.pop_front();
        }
    }
    pub fn snapshot(&self) -> TransferSnapshot {
        let mut events = self.events.lock().unwrap();
        let now = Instant::now();
        while events
            .front()
            .is_some_and(|e| now.duration_since(e.at) > RATE_WINDOW)
        {
            events.pop_front();
        }
        let mut up = 0u64;
        let mut down = 0u64;
        let mut files = HashMap::<String, u64>::new();
        for event in events.iter() {
            match event.direction {
                Direction::Upload => up += event.bytes,
                Direction::Download => {
                    down += event.bytes;
                    if let Some(file) = &event.file {
                        *files.entry(file.clone()).or_default() += event.bytes;
                    }
                }
            }
        }
        let elapsed = events.front().map_or(MIN_SAMPLE_WINDOW_SECS, |event| {
            now.duration_since(event.at)
                .as_secs_f64()
                .clamp(MIN_SAMPLE_WINDOW_SECS, RATE_WINDOW.as_secs_f64())
        });
        let per_second = |bytes: u64| (bytes as f64 / elapsed).round() as u64;
        for bytes in files.values_mut() {
            *bytes = per_second(*bytes);
        }
        TransferSnapshot {
            upload_speed: per_second(up),
            download_speed: per_second(down),
            file_download_speeds: files,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_sample_is_visible_immediately_instead_of_divided_by_full_window() {
        let tracker = TransferTracker::default();
        tracker.upload(1_500);
        let snapshot = tracker.snapshot();
        assert!(
            snapshot.upload_speed >= 4_000,
            "首个采样应在 350ms 最小窗口内即时显示"
        );
    }
}
