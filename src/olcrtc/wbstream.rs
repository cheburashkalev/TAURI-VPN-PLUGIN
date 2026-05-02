use crate::{olcrtc::OlcRtcConfig, Result, VpnError};
use livekit::{DataPacket, Room, RoomEvent, RoomOptions};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::mpsc;

const API_BASE: &str = "https://stream.wb.ru";
const LIVEKIT_WS_URL: &str = "wss://wbstream01-el.wb.ru:7880";
const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
const DATA_TOPIC: &str = "olcrtc";
const SEND_QUEUE_SIZE: usize = 5000;

#[derive(Clone)]
pub struct WbStreamPeer {
    room: Arc<Room>,
    send_tx: mpsc::Sender<Vec<u8>>,
    closed: Arc<AtomicBool>,
}

impl WbStreamPeer {
    pub async fn connect(
        config: &OlcRtcConfig,
    ) -> Result<(Self, mpsc::UnboundedReceiver<Vec<u8>>)> {
        let token = room_token(config).await?;
        let (room, mut events) = Room::connect(LIVEKIT_WS_URL, &token, RoomOptions::default())
            .await
            .map_err(|error| {
                VpnError::Engine(format!("WB Stream LiveKit connect failed: {error}"))
            })?;

        let room = Arc::new(room);
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                match event {
                    RoomEvent::DataReceived { payload, topic, .. }
                        if topic.as_deref() == Some(DATA_TOPIC) =>
                    {
                        let _ = tx.send(payload.as_ref().clone());
                    }
                    RoomEvent::Disconnected { .. } => break,
                    _ => {}
                }
            }
        });

        let (send_tx, mut send_rx) = mpsc::channel::<Vec<u8>>(SEND_QUEUE_SIZE);
        let send_room = room.clone();
        tokio::spawn(async move {
            while let Some(payload) = send_rx.recv().await {
                if send_room
                    .local_participant()
                    .publish_data(DataPacket {
                        payload,
                        topic: Some(DATA_TOPIC.into()),
                        reliable: true,
                        destination_identities: Vec::new(),
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        Ok((
            Self {
                room,
                send_tx,
                closed: Arc::new(AtomicBool::new(false)),
            },
            rx,
        ))
    }

    pub async fn send(&self, data: Vec<u8>) -> Result<()> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(VpnError::Engine("WB Stream peer is closed".into()));
        }

        self.send_tx
            .send(data)
            .await
            .map_err(|_| VpnError::Engine("WB Stream send queue is closed".into()))
    }

    pub async fn close(&self) {
        if !self.closed.swap(true, Ordering::Relaxed) {
            let _ = self.room.close().await;
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GuestRegisterRequest {
    display_name: String,
    device: Device,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Device {
    device_name: String,
    device_type: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GuestRegisterResponse {
    access_token: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateRoomRequest {
    room_type: String,
    room_privacy: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateRoomResponse {
    room_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenResponse {
    room_token: String,
}

async fn room_token(config: &OlcRtcConfig) -> Result<String> {
    let access_token = register_guest(&config.display_name).await?;
    let room_id = if config.room_id == "any" {
        create_room(&access_token).await?
    } else {
        config.room_id.clone()
    };
    join_room(&access_token, &room_id).await?;
    get_token(&access_token, &room_id, &config.display_name).await
}

async fn register_guest(display_name: &str) -> Result<String> {
    let response = http_client()
        .post(format!("{API_BASE}/auth/api/v1/auth/user/guest-register"))
        .header(reqwest::header::USER_AGENT, USER_AGENT)
        .json(&GuestRegisterRequest {
            display_name: display_name.into(),
            device: Device {
                device_name: "Windows".into(),
                device_type: "PARTICIPANT_DEVICE_TYPE_WEB_DESKTOP".into(),
            },
        })
        .send()
        .await
        .map_err(|error| VpnError::Engine(format!("WB Stream guest register failed: {error}")))?;
    let response = expect_status(response, &[StatusCode::OK], "WB Stream guest register").await?;
    response
        .json::<GuestRegisterResponse>()
        .await
        .map(|body| body.access_token)
        .map_err(|error| {
            VpnError::Engine(format!("WB Stream guest register decode failed: {error}"))
        })
}

async fn create_room(access_token: &str) -> Result<String> {
    let response = http_client()
        .post(format!("{API_BASE}/api-room/api/v2/room"))
        .header(reqwest::header::USER_AGENT, USER_AGENT)
        .bearer_auth(access_token)
        .json(&CreateRoomRequest {
            room_type: "ROOM_TYPE_ALL_ON_SCREEN".into(),
            room_privacy: "ROOM_PRIVACY_FREE".into(),
        })
        .send()
        .await
        .map_err(|error| VpnError::Engine(format!("WB Stream create room failed: {error}")))?;
    let response = expect_status(
        response,
        &[StatusCode::OK, StatusCode::CREATED],
        "WB Stream create room",
    )
    .await?;
    response
        .json::<CreateRoomResponse>()
        .await
        .map(|body| body.room_id)
        .map_err(|error| VpnError::Engine(format!("WB Stream create room decode failed: {error}")))
}

async fn join_room(access_token: &str, room_id: &str) -> Result<()> {
    let response = http_client()
        .post(format!("{API_BASE}/api-room/api/v1/room/{room_id}/join"))
        .header(reqwest::header::USER_AGENT, USER_AGENT)
        .bearer_auth(access_token)
        .json(&serde_json::json!({}))
        .send()
        .await
        .map_err(|error| VpnError::Engine(format!("WB Stream join room failed: {error}")))?;
    expect_status(response, &[StatusCode::OK], "WB Stream join room")
        .await
        .map(|_| ())
}

async fn get_token(access_token: &str, room_id: &str, display_name: &str) -> Result<String> {
    let response = http_client()
        .get(format!(
            "{API_BASE}/api-room-manager/api/v1/room/{room_id}/token"
        ))
        .header(reqwest::header::USER_AGENT, USER_AGENT)
        .bearer_auth(access_token)
        .query(&[
            ("deviceType", "PARTICIPANT_DEVICE_TYPE_WEB_DESKTOP"),
            ("displayName", display_name),
        ])
        .send()
        .await
        .map_err(|error| VpnError::Engine(format!("WB Stream room token failed: {error}")))?;
    let response = expect_status(response, &[StatusCode::OK], "WB Stream room token").await?;
    response
        .json::<TokenResponse>()
        .await
        .map(|body| body.room_token)
        .map_err(|error| VpnError::Engine(format!("WB Stream room token decode failed: {error}")))
}

async fn expect_status(
    response: reqwest::Response,
    expected: &[StatusCode],
    operation: &str,
) -> Result<reqwest::Response> {
    if expected.contains(&response.status()) {
        return Ok(response);
    }

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    Err(VpnError::Engine(format!(
        "{operation} failed with {status}: {body}"
    )))
}

fn http_client() -> reqwest::Client {
    reqwest::Client::new()
}
