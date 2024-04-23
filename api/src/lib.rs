use base64::prelude::*;
use rsa::rand_core::block;
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
  collections::{HashMap, HashSet},
  net::{SocketAddr, SocketAddrV4},
  str::FromStr,
  time::Duration,
};

#[derive(Deserialize, Serialize, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Transaction {
  from: PublicKey,
  to: PublicKey,
  amount: u64,
  signature: String,
}

fn message_bytes(to: &PublicKey, from_public: &PublicKey, amount: u64) -> Vec<u8> {
  let mut message = Vec::new();
  message.extend(from_public.to_string().bytes());
  message.extend(to.to_string().bytes());
  message.extend(amount.to_be_bytes());
  let mut hasher = sha2::Sha256::new();
  hasher.update(message);
  hasher.finalize().to_vec()
}

impl Transaction {
  pub fn new(to: &PublicKey, from: &SecretKey, amount: u64) -> anyhow::Result<Self> {
    let context = Secp256k1::new();
    let from_public = PublicKey::from_secret_key(&context, from);
    let message = message_bytes(to, &from_public, amount);
    let signature = context.sign_ecdsa(&Message::from_digest_slice(message.as_slice())?, from);
    Ok(Transaction {
      to: to.clone(),
      from: from_public,
      amount,
      signature: signature.to_string(),
    })
  }
  pub fn verify(&self) -> anyhow::Result<bool> {
    let context = Secp256k1::new();
    let message = message_bytes(&self.to, &self.from, self.amount);
    let signature = Signature::from_str(&self.signature)?;
    Ok(
      context
        .verify_ecdsa(
          &Message::from_digest_slice(&message.as_slice())?,
          &signature,
          &self.from,
        )
        .is_ok(),
    )
  }
}

// Lets setup the serialization to store it as a Public Key
pub fn generate_keypair() -> anyhow::Result<(SecretKey, PublicKey)> {
  let secp = Secp256k1::new();
  let mut rng = rand::thread_rng();
  Ok(secp.generate_keypair(&mut rng))
}

fn now() -> u128 {
  use std::time::{SystemTime, UNIX_EPOCH};
  let start = SystemTime::now();
  let since_the_epoch = start
    .duration_since(UNIX_EPOCH)
    .expect("Time went backwards");
  since_the_epoch.as_millis()
}

#[derive(Debug, Serialize, Deserialize, Clone, Hash, Eq, PartialEq)]
struct Block {
  time: u128,
  transaction: Transaction,
  prev_block_hash: String,
  nonce: u64,
  hash: String,
}

impl Block {
  pub fn new(transaction: Transaction, prev_block_hash: String) -> anyhow::Result<Self> {
    let mut block = Block {
      time: now(),
      transaction,
      prev_block_hash,
      nonce: 0,
      hash: String::new(),
    };
    let difficulty = 2;
    block.mine(difficulty)?;
    Ok(block)
  }
  fn mine(&mut self, difficulty: usize) -> anyhow::Result<()> {
    while !self.verify_hash(difficulty) {
      self.nonce += 1;
      self.hash = self.calculate_hash()?;
    }
    Ok(())
  }
  fn verify_hash(&self, difficulty: usize) -> bool {
    let target = "0".repeat(difficulty);
    self.hash.starts_with(&target)
  }
  fn verify(&self, difficulty: usize) -> anyhow::Result<bool> {
    Ok(self.transaction.verify()? && self.verify_hash(difficulty))
  }
  fn calculate_hash(&self) -> anyhow::Result<String> {
    let headers = format!(
      "{}{:?}{}{}",
      self.time,
      message_bytes(
        &self.transaction.to,
        &self.transaction.from,
        self.transaction.amount
      ),
      self.prev_block_hash,
      self.nonce
    );
    let mut hasher = Sha256::new();
    hasher.update(headers);
    Ok(String::from(&BASE64_STANDARD.encode(hasher.finalize())))
  }
}

#[derive(Deserialize, Serialize, Debug, Clone, Hash, Eq, PartialEq)]
pub struct Blockchain {
  chain: Vec<Block>,
}

impl Blockchain {
  pub fn new() -> anyhow::Result<Self> {
    Ok(Blockchain { chain: vec![] })
  }
  pub fn add_block(&mut self, transaction: Transaction) -> anyhow::Result<()> {
    let last_block = &self.chain.last();
    let prev_hash = if let Some(block) = last_block {
      block.hash.clone()
    } else {
      String::from("0")
    };
    let new_block = Block::new(transaction, prev_hash)?;
    self.chain.push(new_block);
    Ok(())
  }
}

#[derive(Debug, Clone)]
pub struct Ledger {
  chain: Blockchain,
  addr: SocketAddr,
  pending_transactions: Vec<Transaction>,
  peers: HashSet<SocketAddr>,
}

impl Ledger {
  pub fn new(initial_peers: HashSet<SocketAddr>, addr: SocketAddr) -> anyhow::Result<Self> {
    Ok(Self {
      chain: Blockchain::new()?,
      peers: initial_peers,
      addr,
      pending_transactions: Vec::new(),
    })
  }
  pub fn get_balance(&self, public_key: &PublicKey) -> anyhow::Result<i64> {
    let mut balance: i64 = 100;
    for transaction in self.chain.chain.iter().map(|element| &element.transaction) {
      // If the user is not involved with the transaction
      // ignore it
      if public_key != &transaction.from && public_key != &transaction.to {
        continue;
      } else if public_key == &transaction.from && public_key == &transaction.to {
        continue;
      } else if public_key == &transaction.to {
        balance += transaction.amount as i64;
      } else if public_key == &transaction.from {
        balance -= transaction.amount as i64;
      }
    }
    Ok(balance)
  }
  pub async fn send(
    &mut self,
    to: &PublicKey,
    from: &SecretKey,
    amount: u64,
  ) -> anyhow::Result<()> {
    let context = Secp256k1::new();
    let from_public_key = PublicKey::from_secret_key(&context, &from);
    let from_balance = self.get_balance(&from_public_key)?;
    if amount as i64 > from_balance {
      return Err(anyhow::Error::msg("insufficient funds for transaction"));
    }
    self.chain.add_block(Transaction::new(to, &from, amount)?)?;
    let client = reqwest::Client::new();
    for peer in &self.peers {
      let data = json!({
        "blockchain": self.get_blockchain()
      });
      client
        .patch(format!("http://{}/chain", peer))
        .json(&data)
        .send()
        .await
        .ok();
    }
    Ok(())
  }
  pub fn get_blockchain(&self) -> Blockchain {
    self.chain.clone()
  }
  pub async fn update_blockchain(&mut self, blockchain: &Blockchain) {
    println!("{:#?}", blockchain);
    self.chain = blockchain.clone();
  }
  pub async fn sync(&mut self) {
    // Sync peers first
    let temp_peers = self.peers.clone();
    let mut usage_map: HashMap<Blockchain, usize> = HashMap::new();
    println!("Temp Peers: {:#?}", temp_peers);
    for peer in &temp_peers {
      println!("My Address: {}", self.addr);
      if peer == &self.addr {
        continue;
      }
      println!("http://{}/peers/", peer);
      match reqwest::Client::new()
        .post(format!("http://{}/peers/{}", peer, self.addr))
        .send()
        .await
      {
        Ok(..) => {}
        Err(err) => println!("{:#?}", err),
      }

      let wrapped_response = reqwest::get(format!("http://{}/peers", peer)).await;
      let Ok(response) = wrapped_response else {
        // Remove peer if there is an error requesting it
        println!("{:#?}", wrapped_response);
        continue;
      };
      let wrapped_json_response = response.json::<Vec<SocketAddr>>().await;
      // let wrapped_json_response = response.text().await;
      let Ok(res_peers) = wrapped_json_response else {
        println!("{:#?}", wrapped_json_response);
        continue;
      };
      println!("res_peers = {:#?}", res_peers);
      self.peers.extend(res_peers);
      let request = reqwest::Client::new()
        .get(format!("http://{}/chain", peer))
        .timeout(Duration::from_secs(4))
        .send()
        .await;
      let Ok(response) = request else {
        // Remove peer if there is an error requesting it
        println!("failed to get chain, {:#?}", request);
        continue;
      };
      let Ok(blockchain) = response.json::<Blockchain>().await else {
        println!("failed to parse chain");
        continue;
      };
      let count = *usage_map.get(&blockchain).unwrap_or(&0);
      usage_map.insert(blockchain, count + 1);
    }
    let count = *usage_map.get(&self.chain).unwrap_or(&0);
    usage_map.insert(self.chain.clone(), count + 1);
    let (Some(most_popular_blockchain), _) = usage_map.iter().fold(
      (None, &0usize),
      |(acc_blockchain, acc_count), (blockchain, count)| {
        if count > acc_count {
          (Some(blockchain), count)
        } else {
          (acc_blockchain, acc_count)
        }
      },
    ) else {
      return;
    };
    self.update_blockchain(most_popular_blockchain).await;
  }
  pub fn add_peer(&mut self, new_addr: SocketAddr) {
    println!("Adding {} as a peer", new_addr);
    self.peers.insert(new_addr);
    println!("New Peers List {:#?}", self.peers);
  }
  pub fn get_peers(&self) -> HashSet<SocketAddr> {
    self.peers.clone()
  }
}
