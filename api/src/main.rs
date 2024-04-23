use std::{
  collections::HashSet,
  env::Args,
  net::{SocketAddr, SocketAddrV4},
  str::FromStr,
  sync::Arc,
  time::Duration,
};

use axum::{
  body::Body,
  extract::{ConnectInfo, Path, RawPathParams, State},
  http::StatusCode,
  response::{IntoResponse, Response},
  routing::{get, patch, post, Route},
  Json, Router,
};
use secp256k1::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use tanishqoin_api::{generate_keypair, Blockchain, Ledger};
use tokio::{net::TcpListener, sync::Mutex, time};

#[derive(Clone)]
struct AppState {
  ledger: Ledger,
}

impl AppState {
  fn new() -> anyhow::Result<AppState> {
    Ok(AppState {
      ledger: Ledger::new(
        HashSet::from([SocketAddr::from_str("127.0.0.1:3000")?]),
        my_addr(),
      )?,
    })
  }
}

pub fn my_addr() -> SocketAddr {
  let args: Vec<String> = std::env::args().collect();
  let port = args.get(1).unwrap_or(&String::from("3000")).clone();
  SocketAddr::from_str(&format!("127.0.0.1:{}", port)).unwrap()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  let args: Vec<String> = std::env::args().collect();
  let port = args.get(1).unwrap_or(&String::from("3000")).clone();

  tracing_subscriber::fmt::init();

  let state = Arc::new(Mutex::new(AppState::new()?));

  let app = Router::new()
    .route("/", get(root))
    .nest(
      "/wallet",
      Router::new()
        .route("/create", post(create_keypair))
        .route("/balance/:public_key", get(get_balance))
        .route("/send", post(send)),
    )
    .nest(
      "/peers",
      Router::new()
        .route("/", get(get_peers))
        .route("/:addr", post(add_peer)),
    )
    .nest(
      "/chain",
      Router::new()
        .route("/", get(get_blockchain))
        .route("/", patch(update_blockchain)),
    )
    .with_state(state.clone())
    .into_make_service_with_connect_info::<SocketAddr>();

  tokio::spawn(async move {
    let mut interval = time::interval(Duration::from_secs(10));
    loop {
      interval.tick().await;
      state.lock().await.ledger.sync().await;
    }
  });

  let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
    .await
    .unwrap();
  println!("Listening on port {port}");
  axum::serve(listener, app).await?;

  Ok(())
}

async fn root() -> Response {
  (StatusCode::OK).into_response()
}

#[derive(Serialize, Deserialize)]
struct CreateKeyPairResponse {
  secret_key: String,
  public_key: String,
}

async fn create_keypair() -> Response {
  let Ok((secret_key, public_key)) = generate_keypair() else {
    return (
      StatusCode::INTERNAL_SERVER_ERROR,
      String::from("could not generate private key"),
    )
      .into_response();
  };
  (
    StatusCode::OK,
    Json(CreateKeyPairResponse {
      secret_key: secret_key.display_secret().to_string(),
      public_key: public_key.to_string(),
    }),
  )
    .into_response()
}

#[derive(Serialize, Deserialize)]
struct GetBalanceParams {
  public_key: String,
}

#[derive(Serialize, Deserialize)]
struct GetBalanceResponse {
  balance: i64,
}

#[axum::debug_handler]
async fn get_balance(
  Path(params): Path<GetBalanceParams>,
  State(state): State<Arc<Mutex<AppState>>>,
) -> Response {
  let Ok(public_key) = PublicKey::from_str(&params.public_key) else {
    return (
      StatusCode::BAD_REQUEST,
      String::from("could not parse public key"),
    )
      .into_response();
  };
  let Ok(balance) = state.lock().await.ledger.get_balance(&public_key) else {
    return (
      StatusCode::INTERNAL_SERVER_ERROR,
      String::from("could not get balance"),
    )
      .into_response();
  };
  (StatusCode::OK, Json(GetBalanceResponse { balance })).into_response()
}

#[derive(Serialize, Deserialize)]
struct SendBody {
  to_public_key: String,
  from_secret_key: String,
  amount: u64,
}

async fn send(
  State(app_state): State<Arc<Mutex<AppState>>>,
  Json(params): Json<SendBody>,
) -> Response {
  let Ok(to_public_key) = PublicKey::from_str(&params.to_public_key) else {
    return (
      StatusCode::BAD_REQUEST,
      String::from("invalid public key for sending to"),
    )
      .into_response();
  };
  let Ok(from_secret_key) = SecretKey::from_str(&params.from_secret_key) else {
    return (
      StatusCode::BAD_REQUEST,
      String::from("invalid private key for sending from"),
    )
      .into_response();
  };
  match app_state
    .lock()
    .await
    .ledger
    .send(&to_public_key, &from_secret_key, params.amount)
    .await
  {
    Ok(..) => (StatusCode::OK).into_response(),
    Err(..) => (StatusCode::INTERNAL_SERVER_ERROR).into_response(),
  }
}

#[derive(Deserialize)]
struct AddPeerPath {
  addr: SocketAddr,
}

async fn add_peer(
  State(app_state): State<Arc<Mutex<AppState>>>,
  Path(path): Path<AddPeerPath>,
) -> Response {
  app_state.lock().await.ledger.add_peer(path.addr);
  (StatusCode::OK).into_response()
}

async fn get_blockchain(State(app_state): State<Arc<Mutex<AppState>>>) -> Response {
  (
    StatusCode::OK,
    Json(app_state.lock().await.ledger.get_blockchain()),
  )
    .into_response()
}

#[derive(Deserialize, Serialize)]
struct UpdateBlockchainBody {
  blockchain: Blockchain,
}

async fn update_blockchain(
  State(app_state): State<Arc<Mutex<AppState>>>,
  Json(body): Json<UpdateBlockchainBody>,
) -> Response {
  app_state
    .lock()
    .await
    .ledger
    .update_blockchain(&body.blockchain)
    .await;
  (StatusCode::OK).into_response()
}

async fn get_peers(State(app_state): State<Arc<Mutex<AppState>>>) -> Response {
  (
    StatusCode::OK,
    Json(app_state.lock().await.ledger.get_peers()),
  )
    .into_response()
}
