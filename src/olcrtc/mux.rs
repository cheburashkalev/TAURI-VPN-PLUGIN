use crate::{Result, VpnError};
use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc,
    },
};
use tokio::sync::{Mutex, Notify};

const HEADER_SIZE: usize = 12;
const CHUNK_SIZE: usize = 7000;
const CONTROL_STREAM_ID: u16 = 0xFFFF;
const CONTROL_RESET_CLIENT: u32 = 1;

type SendFuture = Pin<Box<dyn Future<Output = Result<()>> + Send>>;
type SendFn = Arc<dyn Fn(Vec<u8>) -> SendFuture + Send + Sync>;

pub struct Multiplexer {
    client_id: u32,
    streams: Mutex<BTreeMap<u16, Stream>>,
    next_id: AtomicU16,
    send: SendFn,
}

#[derive(Default)]
struct Stream {
    client_id: u32,
    recv_buf: Vec<u8>,
    closed: bool,
    next_recv_seq: u32,
    next_send_seq: u32,
    out_of_order: BTreeMap<u32, Vec<u8>>,
    notify: Arc<Notify>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ControlFrame {
    client_id: u32,
    kind: u32,
}

impl Multiplexer {
    pub fn new(
        client_id: u32,
        send: impl Fn(Vec<u8>) -> SendFuture + Send + Sync + 'static,
    ) -> Self {
        Self {
            client_id,
            streams: Mutex::new(BTreeMap::new()),
            next_id: AtomicU16::new(1),
            send: Arc::new(send),
        }
    }

    pub async fn open_stream(&self) -> u16 {
        let mut streams = self.streams.lock().await;
        loop {
            let sid = self.next_id.fetch_add(1, Ordering::Relaxed);
            let sid = if sid == 0 { 1 } else { sid };
            if let std::collections::btree_map::Entry::Vacant(entry) = streams.entry(sid) {
                entry.insert(Stream {
                    client_id: 0,
                    notify: Arc::new(Notify::new()),
                    ..Stream::default()
                });
                return sid;
            }
        }
    }

    pub async fn send_data(&self, sid: u16, data: &[u8]) -> Result<()> {
        for chunk in data.chunks(CHUNK_SIZE) {
            let seq = {
                let mut streams = self.streams.lock().await;
                let Some(stream) = streams.get_mut(&sid) else {
                    return Ok(());
                };
                if stream.closed {
                    return Ok(());
                }
                let seq = stream.next_send_seq;
                stream.next_send_seq = stream.next_send_seq.wrapping_add(1);
                seq
            };

            let mut frame = vec![0_u8; HEADER_SIZE + chunk.len()];
            frame[0..4].copy_from_slice(&self.client_id.to_be_bytes());
            frame[4..6].copy_from_slice(&sid.to_be_bytes());
            frame[6..8].copy_from_slice(&(chunk.len() as u16).to_be_bytes());
            frame[8..12].copy_from_slice(&seq.to_be_bytes());
            frame[HEADER_SIZE..].copy_from_slice(chunk);
            (self.send)(frame).await?;
        }
        Ok(())
    }

    pub async fn close_stream(&self, sid: u16) -> Result<()> {
        {
            let mut streams = self.streams.lock().await;
            if let Some(stream) = streams.get_mut(&sid) {
                stream.closed = true;
                stream.notify.notify_one();
            }
        }

        let mut frame = vec![0_u8; HEADER_SIZE];
        frame[0..4].copy_from_slice(&self.client_id.to_be_bytes());
        frame[4..6].copy_from_slice(&sid.to_be_bytes());
        (self.send)(frame).await
    }

    pub async fn send_client_reset(&self) -> Result<()> {
        if self.client_id == 0 {
            return Err(VpnError::Engine(
                "OLC RTC client reset requires a non-zero client id".into(),
            ));
        }

        let mut frame = vec![0_u8; HEADER_SIZE];
        frame[0..4].copy_from_slice(&self.client_id.to_be_bytes());
        frame[4..6].copy_from_slice(&CONTROL_STREAM_ID.to_be_bytes());
        frame[6..8].copy_from_slice(&u16::MAX.to_be_bytes());
        frame[8..12].copy_from_slice(&CONTROL_RESET_CLIENT.to_be_bytes());
        (self.send)(frame).await
    }

    pub async fn handle_frame(&self, frame: &[u8]) {
        if frame.len() < HEADER_SIZE {
            return;
        }

        if let Some(control) = parse_control_frame(frame) {
            if control.kind == CONTROL_RESET_CLIENT {
                self.reset_client(control.client_id).await;
            }
            return;
        }

        let client_id = u32::from_be_bytes(frame[0..4].try_into().unwrap());
        let sid = u16::from_be_bytes(frame[4..6].try_into().unwrap());
        let length = u16::from_be_bytes(frame[6..8].try_into().unwrap()) as usize;
        let seq = u32::from_be_bytes(frame[8..12].try_into().unwrap());

        if length == 0 {
            self.mark_closed(sid, client_id).await;
            return;
        }
        if frame.len() < HEADER_SIZE + length {
            return;
        }

        let payload = &frame[HEADER_SIZE..HEADER_SIZE + length];
        let notify = {
            let mut streams = self.streams.lock().await;
            let stream = streams.entry(sid).or_insert_with(|| Stream {
                client_id,
                notify: Arc::new(Notify::new()),
                ..Stream::default()
            });
            if stream.client_id != client_id {
                let notify = stream.notify.clone();
                *stream = Stream {
                    client_id,
                    notify,
                    ..Stream::default()
                };
            }

            if seq == stream.next_recv_seq {
                stream.recv_buf.extend_from_slice(payload);
                stream.next_recv_seq = stream.next_recv_seq.wrapping_add(1);
                while let Some(data) = stream.out_of_order.remove(&stream.next_recv_seq) {
                    stream.recv_buf.extend(data);
                    stream.next_recv_seq = stream.next_recv_seq.wrapping_add(1);
                }
                Some(stream.notify.clone())
            } else if seq > stream.next_recv_seq && stream.out_of_order.len() < 100 {
                stream.out_of_order.insert(seq, payload.to_vec());
                None
            } else {
                None
            }
        };

        if let Some(notify) = notify {
            notify.notify_one();
        }
    }

    pub async fn read_stream(&self, sid: u16) -> Vec<u8> {
        let mut streams = self.streams.lock().await;
        let Some(stream) = streams.get_mut(&sid) else {
            return Vec::new();
        };
        std::mem::take(&mut stream.recv_buf)
    }

    pub async fn wait_for_data(&self, sid: u16) {
        loop {
            let notify = {
                let mut streams = self.streams.lock().await;
                let stream = streams.entry(sid).or_insert_with(|| Stream {
                    client_id: self.client_id,
                    notify: Arc::new(Notify::new()),
                    ..Stream::default()
                });
                if !stream.recv_buf.is_empty() || stream.closed {
                    return;
                }
                stream.notify.clone()
            };

            notify.notified().await;
        }
    }

    pub async fn stream_closed(&self, sid: u16) -> bool {
        let streams = self.streams.lock().await;
        streams
            .get(&sid)
            .map(|stream| stream.closed)
            .unwrap_or(true)
    }

    async fn mark_closed(&self, sid: u16, client_id: u32) {
        let notify = {
            let mut streams = self.streams.lock().await;
            streams.get_mut(&sid).and_then(|stream| {
                if stream.client_id == client_id {
                    stream.closed = true;
                    Some(stream.notify.clone())
                } else {
                    None
                }
            })
        };
        if let Some(notify) = notify {
            notify.notify_one();
        }
    }

    async fn reset_client(&self, client_id: u32) {
        let mut streams = self.streams.lock().await;
        streams.retain(|_, stream| {
            if stream.client_id == client_id {
                stream.closed = true;
                stream.notify.notify_one();
                false
            } else {
                true
            }
        });
    }
}

fn parse_control_frame(frame: &[u8]) -> Option<ControlFrame> {
    let sid = u16::from_be_bytes(frame[4..6].try_into().ok()?);
    let length = u16::from_be_bytes(frame[6..8].try_into().ok()?);
    if sid != CONTROL_STREAM_ID || length != u16::MAX {
        return None;
    }
    Some(ControlFrame {
        client_id: u32::from_be_bytes(frame[0..4].try_into().ok()?),
        kind: u32::from_be_bytes(frame[8..12].try_into().ok()?),
    })
}

#[cfg(test)]
mod tests {
    use super::Multiplexer;
    use crate::Result;
    use std::sync::Arc;
    use tokio::{
        sync::Mutex,
        time::{timeout, Duration},
    };

    #[tokio::test]
    async fn frames_are_sent_with_olcrtc_header() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mux = Multiplexer::new(0x01020304, {
            let sent = sent.clone();
            move |frame| {
                let sent = sent.clone();
                Box::pin(async move {
                    sent.lock().await.push(frame);
                    Ok(())
                })
            }
        });

        let sid = mux.open_stream().await;
        mux.send_data(sid, b"abc").await.unwrap();

        let frames = sent.lock().await;
        assert_eq!(&frames[0][0..4], &[1, 2, 3, 4]);
        assert_eq!(u16::from_be_bytes(frames[0][4..6].try_into().unwrap()), sid);
        assert_eq!(&frames[0][12..], b"abc");
    }

    #[tokio::test]
    async fn received_frames_are_buffered_by_sequence() -> Result<()> {
        let mux = Multiplexer::new(1, |_| Box::pin(async { Ok(()) }));
        let sid = mux.open_stream().await;

        let mut frame = vec![0_u8; 15];
        frame[0..4].copy_from_slice(&2_u32.to_be_bytes());
        frame[4..6].copy_from_slice(&sid.to_be_bytes());
        frame[6..8].copy_from_slice(&3_u16.to_be_bytes());
        frame[8..12].copy_from_slice(&0_u32.to_be_bytes());
        frame[12..].copy_from_slice(b"hey");

        mux.handle_frame(&frame).await;
        assert_eq!(mux.read_stream(sid).await, b"hey");
        Ok(())
    }

    #[tokio::test]
    async fn server_response_wakes_waiter_on_client_opened_stream() -> Result<()> {
        let mux = Arc::new(Multiplexer::new(0x01020304, |_| Box::pin(async { Ok(()) })));
        let sid = mux.open_stream().await;

        let waiter = {
            let mux = mux.clone();
            tokio::spawn(async move {
                mux.wait_for_data(sid).await;
            })
        };

        tokio::task::yield_now().await;

        let mut frame = vec![0_u8; 13];
        frame[0..4].copy_from_slice(&0_u32.to_be_bytes());
        frame[4..6].copy_from_slice(&sid.to_be_bytes());
        frame[6..8].copy_from_slice(&1_u16.to_be_bytes());
        frame[8..12].copy_from_slice(&0_u32.to_be_bytes());
        frame[12] = 0;

        mux.handle_frame(&frame).await;
        timeout(Duration::from_millis(50), waiter)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(mux.read_stream(sid).await, vec![0]);
        Ok(())
    }

    #[tokio::test]
    async fn wait_for_data_returns_when_data_arrived_before_wait() -> Result<()> {
        let mux = Multiplexer::new(1, |_| Box::pin(async { Ok(()) }));
        let sid = mux.open_stream().await;

        let mut frame = vec![0_u8; 13];
        frame[0..4].copy_from_slice(&0_u32.to_be_bytes());
        frame[4..6].copy_from_slice(&sid.to_be_bytes());
        frame[6..8].copy_from_slice(&1_u16.to_be_bytes());
        frame[8..12].copy_from_slice(&0_u32.to_be_bytes());
        frame[12] = 0;

        mux.handle_frame(&frame).await;
        timeout(Duration::from_millis(50), mux.wait_for_data(sid))
            .await
            .unwrap();
        assert_eq!(mux.read_stream(sid).await, vec![0]);
        Ok(())
    }
}
