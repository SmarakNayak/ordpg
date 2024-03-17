use self::migrate::Migrator;

use super::*;
use aws_config::imds::client;
use axum_server::Handle;
use mysql_async::Params;
use serde_json::to_string;
use crate::subcommand::server;
use crate::index::fetcher;

use mysql_async::TxOpts;
use mysql_async::Pool;
use mysql_async::prelude::Queryable;
use mysql_async::params;
use mysql_async::Row;
use tokio::sync::Semaphore;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use serde::Serialize;
use sha256::digest;

use s3::operation::get_object::GetObjectOutput;
use aws_sdk_s3 as s3;	
use s3::primitives::ByteStream;	
use s3::error::ProvideErrorMetadata;

use axum::{
  routing::get,
  Json, 
  Router,
  extract::{Path, State, Query},
  body::{Body, BoxBody},
  middleware::map_response,
  http::StatusCode,
  response::IntoResponse,
};
use axum_session::{Session, SessionNullPool, SessionConfig, SessionStore, SessionLayer};

use tower_http::trace::TraceLayer;
use tower_http::trace::DefaultMakeSpan;
use tracing::Span;
use http::{Request, Response};
use tracing::Level as TraceLevel;

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::thread::JoinHandle;
use rand::Rng;
use rand::SeedableRng;

use serde_json::{Value as JsonValue, value::Number as JsonNumber};
use ciborium::value::Value as CborValue;
use bytes::Bytes;
use futures::StreamExt;
use csv::Writer;
use csv::WriterBuilder;

use deadpool_postgres::{Config as deadpoolConfig, Manager, ManagerConfig, Pool as deadpool, RecyclingMethod};
use tokio_postgres::{NoTls, Error};
use tokio_postgres::binary_copy::BinaryCopyInWriter;
use tokio_postgres::types::{ToSql, Type};
use futures::pin_mut;

#[derive(Debug, Parser, Clone)]
pub(crate) struct Vermilion {
  #[arg(
    long,
    help = "Listen on <ADDRESS> for incoming requests. [default: 0.0.0.0]"
  )]
  pub(crate) address: Option<String>,
  #[arg(
    long,
    help = "Request ACME TLS certificate for <ACME_DOMAIN>. This ord instance must be reachable at <ACME_DOMAIN>:443 to respond to Let's Encrypt ACME challenges."
  )]
  pub(crate) acme_domain: Vec<String>,
  #[arg(
    long,
    help = "Use <CSP_ORIGIN> in Content-Security-Policy header. Set this to the public-facing URL of your ord instance."
  )]
  pub(crate) csp_origin: Option<String>,
  #[arg(
    long,
    help = "Listen on <HTTP_PORT> for incoming HTTP requests. [default: 80]"
  )]
  pub(crate) http_port: Option<u16>,
  #[arg(
    long,
    group = "port",
    help = "Listen on <HTTPS_PORT> for incoming HTTPS requests. [default: 443]"
  )]
  pub(crate) https_port: Option<u16>,
  #[arg(long, help = "Store ACME TLS certificates in <ACME_CACHE>.")]
  pub(crate) acme_cache: Option<PathBuf>,
  #[arg(long, help = "Provide ACME contact <ACME_CONTACT>.")]
  pub(crate) acme_contact: Vec<String>,
  #[arg(long, help = "Serve HTTP traffic on <HTTP_PORT>.")]
  pub(crate) http: bool,
  #[arg(long, help = "Serve HTTPS traffic on <HTTPS_PORT>.")]
  pub(crate) https: bool,
  #[arg(long, help = "Redirect HTTP traffic to HTTPS.")]
  pub(crate) redirect_http_to_https: bool,
  #[arg(long, help = "Disable JSON API.")]
  pub(crate) disable_json_api: bool,
  #[arg(
    long,
    help = "Decompress encoded content. Currently only supports brotli. Be careful using this on production instances. A decompressed inscription may be arbitrarily large, making decompression a DoS vector."
  )]
  pub(crate) decompress: bool,
  #[arg(long, alias = "nosync", help = "Do not update the index.")]
  pub(crate) no_sync: bool,
  #[arg(
    long,
    help = "Listen on <HTTP_PORT> for incoming REST requests. [default: 81]."
  )]
  pub(crate) api_http_port: Option<u16>,
  #[arg(
    long,
    help = "Number of threads to use when uploading content and metadata. [default: 1]."
  )]
  pub(crate) n_threads: Option<u16>,
  #[arg(long, help = "Only run api server, do not run indexer. [default: false].")]
  pub(crate) run_api_server_only: bool,
  #[arg(long, help = "Run migration script. [default: false].")]
  pub(crate) run_migration_script: bool
}

#[derive(Clone, Serialize)]
pub struct Metadata {  
  sequence_number: i64,
  id: String,
  content_length: Option<i64>,
  content_type: Option<String>,
  content_encoding: Option<String>,
  genesis_fee: i64,
  genesis_height: i64,
  genesis_transaction: String,
  pointer: Option<i64>,
  number: i64,
  parent: Option<String>,
  delegate: Option<String>,
  metaprotocol: Option<String>,
  embedded_metadata: Option<String>,
  sat: Option<i64>,
  satributes: Vec<String>,
  charms: Option<i16>,
  timestamp: i64,
  sha256: Option<String>,
  text: Option<String>,
  is_json: bool,
  is_maybe_json: bool,
  is_bitmap_style: bool,
  is_recursive: bool
}

#[derive(Clone, Serialize)]
pub struct SatMetadata {
  sat: i64,
  satributes: Vec<String>,
  decimal: String,
  degree: String,
  name: String,
  block: i64,
  cycle: i64,
  epoch: i64,
  period: i64,
  third: i64,
  rarity: String,
  percentile: String,
  timestamp: i64
}

#[derive(Serialize)]
pub struct Satribute {
  sat: i64,
  satribute: String,
}

#[derive(Serialize)]
pub struct ContentBlob {
  sha256: String,
  content: Vec<u8>,
  content_type: String
}

#[derive(Clone, Serialize)]
pub struct Transfer {
  id: String,
  block_number: i64,
  block_timestamp: i64,
  satpoint: String,
  transaction: String,
  vout: i32,
  offset: i64,
  address: String,
  is_genesis: bool
}

#[derive(Clone, Serialize)]
pub struct TransferWithMetadata {
  id: String,
  block_number: i64,
  block_timestamp: i64,
  satpoint: String,
  transaction: String,
  vout: i64,
  offset: i64,
  address: String,
  is_genesis: bool,
  content_length: Option<i64>,
  content_type: Option<String>,
  content_encoding: Option<String>,
  genesis_fee: i64,
  genesis_height: i64,
  genesis_transaction: String,
  pointer: Option<i64>,
  number: i64,
  sequence_number: Option<i64>,
  sat: Option<i64>,
  charms: Option<i16>,
  parent: Option<String>,
  delegate: Option<String>,
  metaprotocol: Option<String>,
  embedded_metadata: Option<String>,
  timestamp: i64,
  sha256: Option<String>,
  text: Option<String>,
  is_json: bool,
  is_maybe_json: bool,
  is_bitmap_style: bool,
  is_recursive: bool
}

#[derive(Clone, Serialize)]
pub struct BlockHeight {
  block_number: i64,
  block_timestamp: i64
}

#[derive(Clone, Serialize)]
pub struct Content {
  content: Vec<u8>,
  content_type: Option<String>
}

#[derive(Clone, Serialize)]
pub struct InscriptionNumberEdition {
  id: String,
  number: i64,
  edition: i64,
  total: i64
}

#[derive(Clone, Serialize)]
pub struct InscriptionMetadataForBlock {
  id: String,
  content_length: Option<i64>,
  content_type: Option<String>,
  genesis_fee: i64,
  genesis_height: i64,
  number: i64,
  timestamp: i64
}

#[derive(Deserialize)]
pub struct QueryNumber {
  n: u32
}

#[derive(Deserialize)]
pub struct InscriptionQueryParams {
  content_types: Option<String>,
  satributes: Option<String>,
  sort_by: Option<String>,
  page_number: Option<usize>,
  page_size: Option<usize>
}

pub struct ParsedInscriptionQueryParams {
  content_types: Vec<String>,
  satributes: Vec<String>,
  sort_by: String,
  page_number: usize,
  page_size: usize
}

impl From<InscriptionQueryParams> for ParsedInscriptionQueryParams {
  fn from(params: InscriptionQueryParams) -> Self {
      Self {
        content_types: params.content_types.map_or(Vec::new(), |v| v.split(",").map(|s| s.to_string()).collect()),
        satributes: params.satributes.map_or(Vec::new(), |v| v.split(",").map(|s| s.to_string()).collect()),
        sort_by: params.sort_by.map_or("newest".to_string(), |v| v),
        page_number: params.page_number.map_or(0, |v| v),
        page_size: params.page_size.map_or(10, |v| v),
      }
  }
}

pub struct RandomInscriptionBand {
  sequence_number: i64,
  start: f64,
  end: f64
}

pub struct SequenceNumberStatus {
  sequence_number: u64,
  status: String
}

#[derive(Clone, Deserialize)]
pub struct SatributeCriteria {
  satribute: String,
  sat: Option<u64>,
  sat_range_start: Option<u64>,
  sat_range_end: Option<u64>,
  block: Option<u32>,
  block_range_start: Option<u32>,
  block_range_end: Option<u32>,
}

#[derive(Clone,PartialEq, PartialOrd, Ord, Eq)]
pub struct IndexerTimings {
  inscription_start: u64,
  inscription_end: u64,
  acquire_permit_start: Instant,
  acquire_permit_end: Instant,
  get_numbers_start: Instant,
  get_numbers_end: Instant,
  get_id_start: Instant,
  get_id_end: Instant,
  get_inscription_start: Instant,
  get_inscription_end: Instant,
  upload_content_start: Instant,
  upload_content_end: Instant,
  get_metadata_start: Instant,
  get_metadata_end: Instant,
  retrieval: Duration,
  insertion: Duration,
  metadata_insertion: Duration,
  sat_insertion: Duration,
  edition_insertion: Duration,
  content_insertion: Duration,
  locking: Duration
}

#[derive(Clone)]
pub struct ApiServerConfig {
  pool: mysql_async::Pool,
  deadpool: deadpool,
  s3client: s3::Client,
  bucket_name: String
}

const INDEX_BATCH_SIZE: usize = 1;

impl Vermilion {
  pub(crate) fn run(self, options: Options) -> SubcommandResult {
    //1. Run Vermilion Server
    println!("Vermilion Server Starting");
    let vermilion_server_clone = self.clone();
    let vermilion_server_thread = vermilion_server_clone.run_vermilion_server(options.clone());

    if self.run_api_server_only {//If only running api server, block here, early return on ctrl-c
      let rt = Runtime::new().unwrap();
      rt.block_on(async {
        loop {            
          if SHUTTING_DOWN.load(atomic::Ordering::Relaxed) {
            break;
          }
          tokio::time::sleep(Duration::from_secs(10)).await;
        }          
      });
      return Ok(None);
    }

    //2. Run Ordinals Server
    println!("Ordinals Server Starting");
    let index = Arc::new(Index::open(&options)?);
    let handle = axum_server::Handle::new();
    LISTENERS.lock().unwrap().push(handle.clone());
    let ordinals_server_clone = self.clone();
    let ordinals_server_thread = ordinals_server_clone.run_ordinals_server(options.clone(), index.clone(), handle);

    //2a. Run Migration script
    let migration_clone = self.clone();
    let migration_script_thread = migration_clone.run_migration_script(options.clone(), index.clone());

    //3. Run Address Indexer
    println!("Address Indexer Starting");
    let address_indexer_clone = self.clone();
    let address_indexer_thread = address_indexer_clone.run_address_indexer(options.clone(), index.clone());

    //4. Run Inscription Indexer
    println!("Inscription Indexer Starting");
    let inscription_indexer_clone = self.clone();
    inscription_indexer_clone.run_inscription_indexer(options.clone(), index.clone()); //this blocks
    println!("Inscription Indexer Stopped");

    //Wait for other threads to finish before exiting
    // vermilion_server_thread.join().unwrap();
    let server_thread_result = ordinals_server_thread.join();
    let address_thread_result = address_indexer_thread.join();
    let migration_thread_result = migration_script_thread.join();
    if server_thread_result.is_err() {
      println!("Error joining ordinals server thread: {:?}", server_thread_result.unwrap_err());
    }
    if address_thread_result.is_err() {
      println!("Error joining address indexer thread: {:?}", address_thread_result.unwrap_err());
    }
    if migration_thread_result.is_err() {
      println!("Error joining migration script thread: {:?}", migration_thread_result.unwrap_err());
    }
    Ok(None)
  }

  pub(crate) fn run_inscription_indexer(self, options: Options, index: Arc<Index>) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
      let config = options.load_config().unwrap();
      let cloned_config = options.clone().load_config().unwrap();
      let url = config.db_connection_string.unwrap();
      let pool = Pool::new(url.as_str());
      let deadpool = match Self::get_deadpool(cloned_config).await {
        Ok(deadpool) => deadpool,
        Err(err) => {
          println!("Error creating deadpool: {:?}", err);
          return;
        }
      };
      let start_number_override = config.start_number_override;
      let s3_config = aws_config::from_env().load().await;
      let s3client = s3::Client::new(&s3_config);
      let s3_bucket_name = config.s3_bucket_name.unwrap();
      let s3_upload_start_number = config.s3_upload_start_number.unwrap_or(0);
      let s3_head_check = config.s3_head_check.unwrap_or(false);
      let n_threads = self.n_threads.unwrap_or(1).into();
      let sem = Arc::new(Semaphore::new(n_threads));
      let status_vector: Arc<Mutex<Vec<SequenceNumberStatus>>> = Arc::new(Mutex::new(Vec::new()));
      let timing_vector: Arc<Mutex<Vec<IndexerTimings>>> = Arc::new(Mutex::new(Vec::new()));
      let init_result = Self::initialize_db_tables(deadpool.clone()).await;
      if init_result.is_err() {
        println!("Error initializing db tables: {:?}", init_result.unwrap_err());
        return;
      }

      let start_number = match start_number_override {
        Some(start_number_override) => start_number_override,
        None => {
          match Self::get_last_number(deadpool.clone()).await {
            Ok(last_number) => (last_number + 1) as u64,
            Err(err) => {
              println!("Error getting last number from db: {:?}, stopping, try restarting process", err);
              return;
            }
          }
        }
      };
      println!("Metadata in db assumed populated up to: {:?}, will only upload metadata for {:?} onwards.", start_number.checked_sub(1), start_number);
      println!("Inscriptions in s3 assumed populated up to: {:?}, will only upload content for {:?} onwards.", std::cmp::max(s3_upload_start_number, start_number).checked_sub(1), std::cmp::max(s3_upload_start_number, start_number));
      let initial = SequenceNumberStatus {
        sequence_number: start_number,
        status: "UNKNOWN".to_string()
      };
      status_vector.lock().await.push(initial);

      // every iteration fetches 1k inscriptions
      let time = Instant::now();
      println!("Starting @ {:?}", time);
      loop {
        let t0 = Instant::now();
        //break if ctrl-c is received
        if SHUTTING_DOWN.load(atomic::Ordering::Relaxed) {
          break;
        }
        let permit = Arc::clone(&sem).acquire_owned().await;
        let cloned_index = index.clone();
        let cloned_pool = pool.clone();
        let cloned_deadpool = deadpool.clone();
        let cloned_s3client = s3client.clone();
        let cloned_bucket_name = s3_bucket_name.clone();
        let cloned_status_vector = status_vector.clone();
        let cloned_timing_vector = timing_vector.clone();
        let fetcher =  match fetcher::Fetcher::new(&options) {
          Ok(fetcher) => fetcher,
          Err(e) => {
            println!("Error creating fetcher: {:?}, waiting a minute", e);
            tokio::time::sleep(Duration::from_secs(60)).await;
            continue;
          }
        };//Need a new fetcher for each thread
        tokio::task::spawn(async move {
          let t1 = Instant::now();
          let _permit = permit;
          let needed_numbers = Self::get_needed_sequence_numbers(cloned_status_vector.clone()).await;
          let mut should_sleep = false;
          let first_number = needed_numbers[0];
          let mut last_number = needed_numbers[needed_numbers.len()-1];
          log::info!("Trying Numbers: {:?}-{:?}", first_number, last_number);          

          //1. Get ids
          let t2 = Instant::now();
          let mut inscription_ids: Vec<InscriptionId> = Vec::new();
          for j in needed_numbers.clone() {
            let inscription_entry = cloned_index.get_inscription_entry_by_sequence_number(j.try_into().unwrap()).unwrap();
            match inscription_entry {
              Some(inscription_entry) => {
                inscription_ids.push(inscription_entry.id);
              },
              None => {
                log::info!("No inscription found for sequence number: {}. Marking as not found. Breaking from loop, sleeping a minute", j);
                last_number = j;
                let status_vector = cloned_status_vector.clone();
                let mut locked_status_vector = status_vector.lock().await;
                for l in needed_numbers.clone() {                  
                  let status = locked_status_vector.iter_mut().find(|x| x.sequence_number == l).unwrap();
                  if l >= j {
                    status.status = "NOT_FOUND_LOCKED".to_string();
                  }                
                }
                should_sleep = true;
                break;
              }
            }
          }
          
          //2. Get inscriptions
          let t3 = Instant::now();
          let cloned_ids = inscription_ids.clone();
          let txs = cloned_index.get_transactions(cloned_ids.into_iter().map(|x| x.txid).collect());
          let err_txs = match txs {
              Ok(txs) => Some(txs),
              Err(error) => {
                println!("Error getting transactions {}-{}: {:?}", first_number, last_number, error);
                let status_vector = cloned_status_vector.clone();
                { //Enclosing braces to drop the mutex so sleep doesn't block
                  let mut locked_status_vector = status_vector.lock().await;
                  for j in needed_numbers.clone() {                  
                    let status = locked_status_vector.iter_mut().find(|x| x.sequence_number == j).unwrap();
                    status.status = "ERROR".to_string();
                  }
                }
                println!("error string: {}", error.to_string());
                if  error.to_string().contains("Failed to fetch raw transaction") || 
                    error.to_string().contains("connection closed") || 
                    error.to_string().contains("error trying to connect") || 
                    error.to_string().contains("end of file") {
                  println!("Pausing for 60s & Breaking from loop");
                  //std::mem::drop(locked_status_vector); //Drop the mutex so sleep doesn't block
                  tokio::time::sleep(Duration::from_secs(60)).await;
                }
                return;
              }
          };
          let clean_txs = err_txs.unwrap();
          let cloned_ids = inscription_ids.clone();
          let id_txs: Vec<_> = cloned_ids.into_iter().zip(clean_txs.into_iter()).collect();
          let mut inscriptions: Vec<Inscription> = Vec::new();
          for (inscription_id, tx) in id_txs {
            let inscription = ParsedEnvelope::from_transaction(&tx)
              .into_iter()
              .nth(inscription_id.index as usize)
              .map(|envelope| envelope.payload)
              .unwrap();
            inscriptions.push(inscription);
          }

          //3. Upload ordinal content to s3 (optional)
          let t4 = Instant::now();
          let cloned_ids = inscription_ids.clone();
          let cloned_inscriptions = inscriptions.clone();
          let number_id_inscriptions: Vec<_> = needed_numbers.clone().into_iter()
            .zip(cloned_ids.into_iter())
            .zip(cloned_inscriptions.into_iter())
            .map(|((x, y), z)| (x, y, z))
            .collect();          
          for (number, inscription_id, inscription) in number_id_inscriptions.clone() {
            if number < s3_upload_start_number {
                continue;
            }
            Self::upload_ordinal_content(&cloned_s3client, &cloned_bucket_name, inscription_id, inscription, s3_head_check).await;	//TODO: Handle errors
          }
          
          //4. Get ordinal metadata
          let t5 = Instant::now();
          let status_vector = cloned_status_vector.clone();

          let mut retrieval = Duration::from_millis(0);
          let mut metadata_vec: Vec<Metadata> = Vec::new();
          let mut sat_metadata_vec: Vec<SatMetadata> = Vec::new();
          for (number, inscription_id, inscription) in number_id_inscriptions {
            let t0 = Instant::now();
            let (metadata, sat_metadata) =  match Self::extract_ordinal_metadata(cloned_index.clone(), inscription_id, inscription.clone()) {
                Ok((metadata, sat_metadata)) => (metadata, sat_metadata),
                Err(error) => {
                  println!("Error: {} extracting metadata for sequence number: {}. Marking as error, will retry", error, number);
                  let mut locked_status_vector = status_vector.lock().await;
                  let status = locked_status_vector.iter_mut().find(|x| x.sequence_number == number).unwrap();
                  status.status = "ERROR_LOCKED".to_string();
                  continue;
                }
            };
            metadata_vec.push(metadata);            
            match sat_metadata {
              Some(sat_metadata) => {
                sat_metadata_vec.push(sat_metadata);
              },
              None => {}                
            }
            let t1 = Instant::now();            
            retrieval += t1.duration_since(t0);
          }

          //4.1 Insert metadata
          let mut client = match cloned_deadpool.get().await {
            Ok(client) => client,
            Err(err) => {
              log::info!("Error getting db client: {:?}, waiting a minute", err);
              let mut locked_status_vector = status_vector.lock().await;
              for j in needed_numbers.clone() {              
                let status = locked_status_vector.iter_mut().find(|x| x.sequence_number == j).unwrap();
                status.status = "ERROR".to_string();
              }
              return;
            }
          };
          let tx = match client.transaction().await{
            Ok(tx) => tx,
            Err(err) => {
              log::info!("Error starting db transaction: {:?}, waiting a minute", err);
              let mut locked_status_vector = status_vector.lock().await;
              for j in needed_numbers.clone() {
                let status = locked_status_vector.iter_mut().find(|x| x.sequence_number == j).unwrap();
                status.status = "ERROR".to_string();
              }
              return;
            }
          };
          let t51 = Instant::now();
          let insert_result = Self::bulk_insert_metadata(&tx, metadata_vec.clone()).await;
          let edition_result = Self::bulk_insert_editions(&tx, metadata_vec).await;
          let t51a = Instant::now();
          let sat_insert_result = Self::bulk_insert_sat_metadata(&tx, sat_metadata_vec.clone()).await;
          let t51b = Instant::now();
          let mut satributes_vec = Vec::new();
          for sat_metadata in sat_metadata_vec.iter() {
            let sat = Sat(sat_metadata.sat as u64);
            for block_rarity in sat.block_rarities().iter() {
              let satribute = Satribute {
                sat: sat_metadata.sat,
                satribute: block_rarity.to_string()
              };
              satributes_vec.push(satribute);
            }
            let rarity = Satribute {
              sat: sat_metadata.sat,
              satribute: sat.rarity().to_string()
            };
            satributes_vec.push(rarity);
          }
          let satribute_insert_result = Self::bulk_insert_satributes(&tx, satributes_vec).await;
          let t51c = Instant::now();
          //4.2 Upload content to db
          let mut content_vec: Vec<ContentBlob> = Vec::new();
          for inscription in inscriptions {
            if let Some(content) = inscription.body() {
              let content_type = match inscription.content_type() {
                  Some(content_type) => content_type,
                  None => ""
              };
              let sha256 = digest(content);
              let content_blob = ContentBlob {
                sha256: sha256.to_string(),
                content: content.to_vec(),
                content_type: content_type.to_string()
              };
              content_vec.push(content_blob);
            }
          }
          let numbers_content = needed_numbers.clone()
            .into_iter()
            .zip(content_vec.into_iter())
            .map(|(x, y)| (x as i64, y))
            .collect::<Vec<_>>();
          let content_result = Self::bulk_insert_content(&tx, numbers_content).await;
          let commit_result = tx.commit().await;
          //4.3 Update status
          let t52 = Instant::now();
          if insert_result.is_err() || sat_insert_result.is_err() || content_result.is_err() || satribute_insert_result.is_err() || commit_result.is_err() || edition_result.is_err() {
            log::info!("Error bulk inserting into db for sequence numbers: {}-{}. Will retry after 60s", first_number, last_number);
            if insert_result.is_err() {
              log::info!("Metadata Error: {:?}", insert_result.unwrap_err());
            }
            if sat_insert_result.is_err() {
              log::info!("Sat Error: {:?}", sat_insert_result.unwrap_err());
            }
            if satribute_insert_result.is_err() {
              log::info!("Satribute Error: {:?}", satribute_insert_result.unwrap_err());
            }
            if content_result.is_err() {
              log::info!("Content Error: {:?}", content_result.unwrap_err());
            }
            if commit_result.is_err() {
              log::info!("Commit Error: {:?}", commit_result.unwrap_err());
            }
            if edition_result.is_err() {
              log::info!("Edition Error: {:?}", edition_result.unwrap_err());
            }
            should_sleep = true;
            let mut locked_status_vector = status_vector.lock().await;
            for j in needed_numbers.clone() {              
              let status = locked_status_vector.iter_mut().find(|x| x.sequence_number == j).unwrap();
              status.status = "ERROR".to_string();
            }
          } else {
            let mut locked_status_vector = status_vector.lock().await;
            for j in needed_numbers.clone() {              
              let status = locked_status_vector.iter_mut().find(|x| x.sequence_number == j).unwrap();
              //_LOCKED state to prevent other threads from changing status before current thread completes
              if status.status != "NOT_FOUND_LOCKED" && status.status != "ERROR_LOCKED" {
                status.status = "SUCCESS".to_string();
              } else if status.status == "NOT_FOUND_LOCKED" {
                status.status = "NOT_FOUND".to_string();
              } else if status.status == "ERROR_LOCKED" {
                status.status = "ERROR".to_string();
              }
            }
          }
          
          //5. Log timings
          let t6 = Instant::now();
          if first_number != last_number {
            log::info!("Finished numbers {} - {}", first_number, last_number);
          }
          let timing = IndexerTimings {
            inscription_start: first_number,
            inscription_end: last_number + 1,
            acquire_permit_start: t0,
            acquire_permit_end: t1,
            get_numbers_start: t1,
            get_numbers_end: t2,
            get_id_start: t2,
            get_id_end: t3,
            get_inscription_start: t3,
            get_inscription_end: t4,
            upload_content_start: t4,
            upload_content_end: t5,
            get_metadata_start: t5,
            get_metadata_end: t6,
            retrieval: retrieval,
            insertion: t52.duration_since(t51),
            metadata_insertion: t51a.duration_since(t51),
            sat_insertion: t51b.duration_since(t51a),
            edition_insertion: t51c.duration_since(t51b),
            content_insertion: t52.duration_since(t51c),
            locking: t6.duration_since(t52)
          };
          cloned_timing_vector.lock().await.push(timing);
          Self::print_index_timings(cloned_timing_vector, n_threads as u32).await;

          //6. Sleep thread if up to date.
          if should_sleep {
            tokio::time::sleep(Duration::from_secs(60)).await;
          }
        });        
        
      }
    })
  }

  pub(crate) fn run_address_indexer(self, options: Options, index: Arc<Index>) -> JoinHandle<()> {
    let address_indexer_thread = thread::spawn(move ||{
      let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
      rt.block_on(async move {
        let config = options.load_config().unwrap();
        let cloned_config = options.clone().load_config().unwrap();
        let url = config.db_connection_string.unwrap();
        let pool = Pool::new(url.as_str());
        let deadpool = match Self::get_deadpool(cloned_config).await {
          Ok(deadpool) => deadpool,
          Err(err) => {
            println!("Error creating deadpool: {:?}", err);
            return;
          }
        };
        let create_tranfer_result = Self::create_transfers_table(deadpool.clone()).await;
        let create_address_result = Self::create_address_table(deadpool.clone()).await;
        let create_blockheight_result = Self::create_blockheight_table(deadpool.clone()).await;
        if create_tranfer_result.is_err() {
          println!("Error creating db tables: {:?}", create_tranfer_result.unwrap_err());
          return;            
        }
        if create_address_result.is_err() {
          println!("Error creating db tables: {:?}", create_address_result.unwrap_err());
          return;
        }
        if create_blockheight_result.is_err() {
          println!("Error creating db tables: {:?}", create_blockheight_result.unwrap_err());
          return;
        }

        let fetcher = fetcher::Fetcher::new(&options).unwrap();
        let first_inscription_height = options.first_inscription_height();
        let mut height = match Self::get_start_block(deadpool.clone()).await {
          Ok(height) => height,
          Err(err) => {
            log::info!("Error getting start block from db: {:?}, waiting a minute", err);
            return;
          }
        };
        log::info!("Address indexing block start height: {:?}", height);
        let mut blockheights = Vec::new();
        loop {
          let t0 = Instant::now();
          // break if ctrl-c is received
          if SHUTTING_DOWN.load(atomic::Ordering::Relaxed) {
            break;
          }

          // make sure block is indexed before requesting transfers
          let indexed_height = index.get_blocks_indexed().unwrap();
          if height > indexed_height {
            log::info!("Requesting block transfers for block: {:?}, only indexed up to: {:?}. Waiting a minute", height, indexed_height);
            tokio::time::sleep(Duration::from_secs(60)).await;
            continue;
          }

          let blockheight = BlockHeight {
            block_number: height as i64,
            block_timestamp: index.block_time(Height(height)).unwrap().timestamp().timestamp_millis()
          };
          blockheights.push(blockheight);

          let mut conn = match deadpool.get().await {
            Ok(conn) => conn,
            Err(err) => {
              log::info!("Error getting db connection: {:?}, waiting a minute", err);
              tokio::time::sleep(Duration::from_secs(60)).await;
              continue;
            }
          };
          let deadpool_tx = match conn.transaction().await {
            Ok(tx) => tx,
            Err(err) => {
              log::info!("Error starting db transaction: {:?}, waiting a minute", err);
              tokio::time::sleep(Duration::from_secs(60)).await;
              continue;
            }
          };

          if height < first_inscription_height {
            if height % 100000 == 0 {
              log::info!("Inserting blockheights @ {}", height);
              let insert = Self::bulk_insert_blockheights(&deadpool_tx, blockheights.clone()).await;
              let commit = deadpool_tx.commit().await;
              if insert.is_err() || commit.is_err() {
                if insert.is_err() {
                  log::info!("Error inserting blockheights into db: {:?}, waiting a minute", insert.unwrap_err());
                }
                if commit.is_err() {
                  log::info!("Error committing blockheights into db: {:?}, waiting a minute", commit.unwrap_err());
                }
                tokio::time::sleep(Duration::from_secs(60)).await;
                continue;
              } else {
                blockheights = Vec::new();
              }
            }
            height += 1;
            continue;
          } else {
            match Self::bulk_insert_blockheights(&deadpool_tx, blockheights.clone()).await {
              Ok(_) => {
                log::debug!("Inserted blockheights @ {}", height);
                blockheights = Vec::new();
              },
              Err(err) => {
                log::info!("Error inserting blockheights into db: {:?}, waiting a minute", err);
                tokio::time::sleep(Duration::from_secs(60)).await;
                continue;
              }
            }
          }

          let t1 = Instant::now();
          let transfers = match index.get_transfers_by_block_height(height) {
            Ok(transfers) => transfers,
            Err(err) => {
              log::info!("Error getting transfers for block height: {:?} - {:?}, waiting a minute", height, err);
              tokio::time::sleep(Duration::from_secs(60)).await;
              continue;
            }
          };
          
          if transfers.len() == 0 {
            log::debug!("No transfers found for block height: {:?}, skipping", height);
            height += 1;
            continue;
          }
          let t2 = Instant::now();
          let mut tx_id_list = transfers.clone().into_iter().map(|(_id, satpoint)| satpoint.outpoint.txid).collect::<Vec<_>>();
          //log::info!("Predupe: {:?}", tx_id_list.len());
          tx_id_list.dedup();
          //log::info!("Postdupe: {:?}", tx_id_list.len());
          let txs = match fetcher.get_transactions(tx_id_list).await {
            Ok(txs) => {
              txs.into_iter().map(|tx| Some(tx)).collect::<Vec<_>>()
            }
            Err(e) => {
              log::info!("Error getting transfer transactions for block height: {:?} - {:?}", height, e);
              if e.to_string().contains("No such mempool or blockchain transaction") || e.to_string().contains("Broken pipe") || e.to_string().contains("end of file") || e.to_string().contains("EOF while parsing") {
                log::info!("Attempting 1 at a time");
                let mut txs = Vec::new();
                for (id, satpoint) in transfers.clone() {
                  let tx = match fetcher.get_transactions(vec![satpoint.outpoint.txid]).await {
                    Ok(mut tx) => Some(tx.pop().unwrap()),
                    Err(e) => {                      
                      let miner_outpoint = OutPoint{
                        txid: Hash::all_zeros(),
                        vout: 0
                      };
                      if satpoint.outpoint != miner_outpoint {
                        log::error!("ERROR: skipped non-miner transfer: {:?} - {:?} - {:?}, trying again in a minute", satpoint.outpoint.txid, id, e);
                        tokio::time::sleep(Duration::from_secs(60)).await;
                        continue;
                      } else {
                        log::debug!("Skipped miner transfer: {:?} for {:?} - {:?}", satpoint.outpoint.txid, id, e);
                      }
                      None
                    }
                  };
                  txs.push(tx)
                }
                txs
              } else {
                log::info!("Unknown Error getting transfer transactions for block height: {:?} - {:?} - Waiting a minute", height, e);
                tokio::time::sleep(Duration::from_secs(60)).await;
                continue;
              }              
            }
          };

          let mut tx_map: HashMap<Txid, Transaction> = HashMap::new();
          for tx in txs {
            if let Some(tx) = tx {
              tx_map.insert(tx.txid(), tx);   
            }
          }

          let t3 = Instant::now();          
          let mut seq_point_address = Vec::new();
          for (sequence_number, satpoint) in transfers {
            let address = if satpoint.outpoint == unbound_outpoint() {
              "unbound".to_string()
            } else {
              let tx = tx_map.get(&satpoint.outpoint.txid).unwrap();
              let output = tx
                .clone()
                .output
                .into_iter()
                .nth(satpoint.outpoint.vout.try_into().unwrap())
                .unwrap();
              let address = options
                .chain()
                .address_from_script(&output.script_pubkey)
                .map(|address| address.to_string())
                .unwrap_or_else(|e| e.to_string());
              address
            };
            seq_point_address.push((sequence_number, satpoint, address));
          }
          let t4 = Instant::now();
          let block_time = index.block_time(Height(height)).unwrap();
          let mut transfer_vec = Vec::new();
          for (sequence_number, point, address) in seq_point_address {
            let entry = index.get_inscription_entry_by_sequence_number(sequence_number).unwrap();
            let id = entry.unwrap().id;
            let transfer = Transfer {
              id: id.to_string(),
              block_number: height.try_into().unwrap(),
              block_timestamp: block_time.timestamp().timestamp_millis(),
              satpoint: point.to_string(),
              transaction: point.outpoint.txid.to_string(),
              vout: point.outpoint.vout as i32,
              offset: point.offset as i64,
              address: address,
              is_genesis: point.outpoint.txid == id.txid && point.outpoint.vout == id.index
            };
            transfer_vec.push(transfer);
          }
          let t5 = Instant::now();
          let insert_transfer_result = Self::bulk_insert_transfers(&deadpool_tx, transfer_vec.clone()).await;
          let t6 = Instant::now();
          let insert_address_result = Self::bulk_insert_addresses(&deadpool_tx, transfer_vec).await;
          let commit_result = deadpool_tx.commit().await;
          if insert_transfer_result.is_err() || insert_address_result.is_err() || commit_result.is_err(){
            log::info!("Error bulk inserting addresses into db for block height: {:?}, waiting a minute", height);
            if insert_transfer_result.is_err() {
              log::info!("Transfer Error: {:?}", insert_transfer_result.unwrap_err());
            }
            if insert_address_result.is_err() {
              log::info!("Address Error: {:?}", insert_address_result.unwrap_err());
            }
            if commit_result.is_err() {
              log::info!("Commit Error: {:?}", commit_result.unwrap_err());
            }
            tokio::time::sleep(Duration::from_secs(60)).await;
            continue;              
          }
          let t7 = Instant::now();
          log::info!("Address indexer: Indexed block: {:?}", height);
          log::info!("Height check: {:?} - Get transfers: {:?} - Get txs: {:?} - Get addresses {:?} - Create Vec: {:?} - Insert transfers: {:?} - Insert addresses: {:?} TOTAL: {:?}", t1.duration_since(t0), t2.duration_since(t1), t3.duration_since(t2), t4.duration_since(t3), t5.duration_since(t4), t6.duration_since(t5), t7.duration_since(t6), t7.duration_since(t0));
          height += 1;
        }
        println!("Address indexer stopped");
      })
    });
    return address_indexer_thread;
  }

  pub(crate) fn run_vermilion_server(self, options: Options) -> JoinHandle<()> {
    let verm_server_thread = thread::spawn(move ||{
      let rt = Runtime::new().unwrap();
      rt.block_on(async move {
        let config = options.load_config().unwrap();
        let config_clone = options.clone().load_config().unwrap();
        let url = config.db_connection_string.unwrap();
        let pool = mysql_async::Pool::new(url.as_str());
        let deadpool = match Self::get_deadpool(config_clone).await {
          Ok(deadpool) => deadpool,
          Err(err) => {
            println!("Error creating deadpool: {:?}", err);
            return;
          }
        };
        let bucket_name = config.s3_bucket_name.unwrap();
        let s3_config = aws_config::from_env().load().await;
        let s3client = s3::Client::new(&s3_config);
        
        let server_config = ApiServerConfig {
          pool: pool,
          deadpool: deadpool,
          s3client: s3client,
          bucket_name: bucket_name
        };

        let session_config = SessionConfig::default()
          .with_table_name("sessions_table");
        let session_store = SessionStore::<SessionNullPool>::new(None, session_config).await.unwrap();

        let app = Router::new()
          .route("/", get(Self::root))
          .route("/home", get(Self::home))
          .route("/inscription/:inscription_id", get(Self::inscription))
          .route("/inscription_number/:number", get(Self::inscription_number))
          .route("/inscription_sha256/:sha256", get(Self::inscription_sha256))
          .route("/inscription_metadata/:inscription_id", get(Self::inscription_metadata))
          .route("/inscription_metadata_number/:number", get(Self::inscription_metadata_number))
          .route("/inscription_editions/:inscription_id", get(Self::inscription_editions))
          .route("/inscription_editions_number/:number", get(Self::inscription_editions_number))
          .route("/inscription_editions_sha256/:sha256", get(Self::inscription_editions_sha256))
          .route("/inscriptions_in_block/:block", get(Self::inscriptions_in_block))
          .route("/inscriptions", get(Self::inscriptions))
          .route("/random_inscription", get(Self::random_inscription))
          .route("/random_inscriptions", get(Self::random_inscriptions))
          .route("/recent_inscriptions", get(Self::recent_inscriptions))
          .route("/inscription_last_transfer/:inscription_id", get(Self::inscription_last_transfer))
          .route("/inscription_last_transfer_number/:number", get(Self::inscription_last_transfer_number))
          .route("/inscription_transfers/:inscription_id", get(Self::inscription_transfers))
          .route("/inscription_transfers_number/:number", get(Self::inscription_transfers_number))
          .route("/inscriptions_in_address/:address", get(Self::inscriptions_in_address))
          .route("/inscriptions_on_sat/:sat", get(Self::inscriptions_on_sat))
          .route("/inscriptions_in_sat_block/:block", get(Self::inscriptions_in_sat_block))
          .route("/sat_metadata/:sat", get(Self::sat_metadata))
          .route("/satributes/:sat", get(Self::satributes))
          .layer(map_response(Self::set_header))
          .layer(
            TraceLayer::new_for_http()
              .make_span_with(DefaultMakeSpan::new().level(TraceLevel::INFO))
              .on_request(|req: &Request<Body>, _span: &Span| {
                tracing::event!(TraceLevel::INFO, "Started processing request {}", req.uri().path());
              })
              .on_response(|res: &Response<BoxBody>, latency: Duration, _span: &Span| {
                tracing::event!(TraceLevel::INFO, "Finished processing request latency={:?} status={:?}", latency, res.status());
              })
          )
          .with_state(server_config)
          .layer(SessionLayer::new(session_store));

        let addr = SocketAddr::from(([127, 0, 0, 1], self.api_http_port.unwrap_or(81)));
        //tracing::debug!("listening on {}", addr);
        axum::Server::bind(&addr)
            .serve(app.into_make_service())
            .with_graceful_shutdown(Self::shutdown_signal())
            .await
            .unwrap();
      });
      println!("Vermilion server stopped");
    });
    return verm_server_thread;
  }

  pub(crate) fn run_ordinals_server(self, options: Options, index: Arc<Index>, handle: Handle) -> JoinHandle<()> {
    //1. Ordinals Server
    let server = server::Server {
      address: self.address,
      acme_domain: self.acme_domain,
      http_port: self.http_port,
      https_port: self.https_port,
      acme_cache: self.acme_cache,
      acme_contact: self.acme_contact,
      http: self.http,
      https: self.https,
      redirect_http_to_https: self.redirect_http_to_https,
      disable_json_api: self.disable_json_api,
      csp_origin: self.csp_origin,
      decompress: self.decompress,
      no_sync: self.no_sync,
    };
    let server_thread = thread::spawn(move || {
      let server_result = server.run(options, index, handle);
      match server_result {
        Ok(_) => {
          println!("Ordinals server stopped");
        },
        Err(err) => {
          println!("Ordinals server failed to start: {:?}", err);
        }
      }
    });
    return server_thread;
  }

  pub(crate) fn run_migration_script(self, options: Options, index: Arc<Index>) -> JoinHandle<()> {
      let migration_thread = thread::spawn(move || {
        if self.run_migration_script {
          println!("Migration Script Starting");
          let migrator = Migrator {
            script_number: 1
          };
          let migration_result = migrator.run(options, index);
          match migration_result {
            Ok(_) => {
              println!("Migration script stopped");
            },
            Err(err) => {
              println!("Migration script failed: {:?}", err);
            }
          }
        }
      });
      return migration_thread;
  }
  
  //Inscription Indexer Helper functions
  pub(crate) async fn upload_ordinal_content(client: &s3::Client, bucket_name: &str, inscription_id: InscriptionId, inscription: Inscription, head_check: bool) {
    let id = inscription_id.to_string();	
    let key = format!("content/{}", id);
    if head_check {
      let head_status = client	
        .head_object()	
        .bucket(bucket_name)	
        .key(key.clone())	
        .send()	
        .await;
      match head_status {	
        Ok(_) => {	
          log::debug!("Ordinal content already exists in S3: {}", id.clone());	
          return;	
        }	
        Err(error) => {	
          if error.to_string() == "service error" {
            let service_error = error.into_service_error();
            if service_error.to_string() != "NotFound" {
              println!("Error checking if ordinal {} exists in S3: {} - {:?} code: {:?}", id.clone(), service_error, service_error.message(), service_error.code());	
              return;	//error
            } else {
              log::trace!("Ordinal {} not found in S3, uploading", id.clone());
            }
          } else {
            println!("Error checking if ordinal {} exists in S3: {} - {:?}", id.clone(), error, error.message());	
            return; //error
          }
        }
      };
    }
    
    let body = Inscription::body(&inscription);	
    let bytes = match body {	
      Some(body) => body.to_vec(),	
      None => {	
        log::debug!("No body found for inscription: {}, filling with empty body", inscription_id);	
        Vec::new()	
      }	
    };	
    let content_type = match Inscription::content_type(&inscription) {	
      Some(content_type) => content_type,	
      None => {	
        log::debug!("No content type found for inscription: {}, filling with empty content type", inscription_id);	
        ""	
      }	
    };
    let put_status = client	
      .put_object()	
      .bucket(bucket_name)	
      .key(key)	
      .body(ByteStream::from(bytes))	
      .content_type(content_type)	
      .send()	
      .await;

    let _ret = match put_status {	
      Ok(put_status) => {	
        log::debug!("Uploaded ordinal content to S3: {}", id.clone());	
        put_status	
      }	
      Err(error) => {	
        log::error!("Error uploading ordinal {} to S3: {} - {:?}", id.clone(), error, error.message());	
        return;	
      }	
    };
  }

  fn is_bitmap_style(input: &str) -> bool {
    let pattern = r"^[^ \n]+[.][^ \n]+$";
    let re = regex::Regex::new(pattern).unwrap();
    re.is_match(input)
  }
  
  fn is_recursive(input: &str) -> bool {
    input.contains("/content")
  }

  fn is_maybe_json(input: &str, content_type: Option<String>) -> bool { 
    let length = input.len();
    if length < 2 {
      return false; // The string is too short
    }
    if content_type.is_some() {
      let content_type = content_type.unwrap();
      if !(content_type.contains("json") || content_type.contains("text/plain")) {
        return false; // The content type is not a text type, don't check for html/svg false positives
      }
    }
    let num_colons = input.chars().filter(|&c| c == ':').count();
    let num_quotes = input.chars().filter(|&c| c == '"').count();
    let num_commas = input.chars().filter(|&c| c == ',').count();
    let ratio = (num_colons as f32 + num_quotes as f32 + num_commas as f32)/ length as f32;
    let first_char = input.chars().next().unwrap();
    let last_char = input.chars().last().unwrap();  
    first_char == '{' || last_char == '}' || ratio > 0.1
  }

  fn cbor_into_string(cbor: CborValue) -> Option<String> {
    match cbor {
        CborValue::Text(string) => Some(string),
        _ => None,
    }
  }

  fn cbor_to_json(cbor: CborValue) -> JsonValue {
    match cbor {
        CborValue::Null => JsonValue::Null,
        CborValue::Bool(boolean) => JsonValue::Bool(boolean),
        CborValue::Text(string) => JsonValue::String(string),
        CborValue::Integer(int) => JsonValue::Number({
            let int: i128 = int.into();
            if let Ok(int) = u64::try_from(int) {
                JsonNumber::from(int)
            } else if let Ok(int) = i64::try_from(int) {
                JsonNumber::from(int)
            } else {
                JsonNumber::from_f64(int as f64).unwrap()
            }
        }),
        CborValue::Float(float) => JsonValue::Number(JsonNumber::from_f64(float).unwrap()),
        CborValue::Array(vec) => JsonValue::Array(vec.into_iter().map(Self::cbor_to_json).collect()),
        CborValue::Map(map) => JsonValue::Object(map.into_iter().map(|(k, v)| (Self::cbor_into_string(k).unwrap(), Self::cbor_to_json(v))).collect()),
        CborValue::Bytes(_) | CborValue::Tag(_, _) => unimplemented!(),
        _ => unimplemented!(),
    }
  }

  pub(crate) fn extract_ordinal_metadata(index: Arc<Index>, inscription_id: InscriptionId, inscription: Inscription) -> Result<(Metadata, Option<SatMetadata>)> {
    let t0 = Instant::now();
    let entry = index
      .get_inscription_entry(inscription_id)
      .unwrap()
      .unwrap();
    let t1 = Instant::now();
    let content_length = match inscription.content_length() {
      Some(content_length) => Some(content_length as i64),
      None => {
        log::debug!("No content length found for inscription: {}, filling with 0", inscription_id);
        Some(0)
      }
    };
    let content_encoding = match inscription.content_encoding() {
      Some(content_encoding) => {
        match content_encoding.to_str() {
          Ok(content_encoding) => Some(content_encoding.to_string()),
          Err(_) => None
        }
      },
      None => None
    };
    let sat = match entry.sat {
      Some(sat) => Some(sat.n() as i64),
      None => {
        None
      }
    };
    let satributes = match entry.sat {
      Some(sat) => {
        let mut satributes = sat.block_rarities().iter().map(|x| x.to_string()).collect::<Vec<String>>();
        if !sat.common() {
          satributes.push(sat.rarity().to_string()); 
        }
        satributes
      },
      None => Vec::new()
    };
    let parent = entry.parent.map_or(None, |parent| Some(parent.to_string()));
    let mut metaprotocol = inscription.metaprotocol().map_or(None, |str| Some(str.to_string()));
    if let Some(mut metaprotocol_inner) = metaprotocol.clone() {
      if metaprotocol_inner.len() > 100 {
        log::warn!("Metaprotocol too long: {} - {}, truncating", inscription_id, metaprotocol_inner);
        //metaprotocol_inner.truncate(100);
        //metaprotocol = Some(metaprotocol_inner);
      }
    }
    let embedded_metadata = inscription.metadata().map_or(None, |cbor| Some(Self::cbor_to_json(cbor).to_string()));
    let sha256 = match inscription.body() {
      Some(body) => {
        let hash = digest(body);
        Some(hash)
      },
      None => {
        None
      }
    };
    let text = match inscription.body() {
      Some(body) => {
        let text = String::from_utf8(body.to_vec());
        match text {
          Ok(text) => Some(text),
          Err(_) => None
        }
      },
      None => {
        None
      }
    };
    let is_json = match inscription.body() {
      Some(body) => {
        let json = serde_json::from_slice::<serde::de::IgnoredAny>(body);
        match json {
          Ok(_) => true,
          Err(_) => false
        }
      },
      None => {
        false
      }
    };
    let is_maybe_json = match text.clone() {
      Some(text) => Self::is_maybe_json(&text, inscription.content_type().map(str::to_string)),
      None => false
    };
    let is_bitmap_style = match text.clone() {
      Some(text) => Self::is_bitmap_style(&text),
      None => false
    };
    let is_recursive = match text.clone() {
      Some(text) => Self::is_recursive(&text),
      None => false
    };
    let metadata = Metadata {
      id: inscription_id.to_string(),
      content_length: content_length,
      content_encoding: content_encoding,
      content_type: inscription.content_type().map(str::to_string),
      genesis_fee: entry.fee.try_into().unwrap(),
      genesis_height: entry.height.try_into().unwrap(),
      genesis_transaction: inscription_id.txid.to_string(),
      pointer: inscription.pointer().map(|value| { value.try_into().unwrap()}),
      number: entry.inscription_number as i64,
      sequence_number: entry.sequence_number as i64,
      parent: parent,
      delegate: inscription.delegate().map(|x| x.to_string()),
      metaprotocol: metaprotocol,
      embedded_metadata: embedded_metadata,
      sat: sat,
      satributes: satributes.clone(),
      charms: Some(entry.charms.try_into().unwrap()),
      timestamp: entry.timestamp.try_into().unwrap(),
      sha256: sha256.clone(),
      text: text,
      is_json: is_json,
      is_maybe_json: is_maybe_json,
      is_bitmap_style: is_bitmap_style,
      is_recursive: is_recursive
    };
    let t2 = Instant::now();
    let sat_metadata = match entry.sat {
      Some(sat) => {
        let sat_blocktime = index.block_time(sat.height())?;
        let sat_metadata = SatMetadata {
          sat: sat.0 as i64,
          satributes: satributes,
          decimal: sat.decimal().to_string(),
          degree: sat.degree().to_string(),
          name: sat.name(),
          block: sat.height().0 as i64,
          cycle: sat.cycle() as i64,
          epoch: sat.epoch().0 as i64,
          period: sat.period() as i64,
          third: sat.third() as i64,
          rarity: sat.rarity().to_string(),
          percentile: sat.percentile(),
          timestamp: sat_blocktime.timestamp().timestamp()
        };
        Some(sat_metadata)
      },
      None => None
    };
    let t3 = Instant::now();

    log::trace!("index: {:?} metadata: {:?} sat: {:?} total: {:?}", t1.duration_since(t0), t2.duration_since(t1), t3.duration_since(t2), t3.duration_since(t0));
    Ok((metadata, sat_metadata))
  }

  pub(crate) async fn initialize_db_tables(pool: deadpool_postgres::Pool) -> anyhow::Result<()> {
    Self::create_metadata_table(pool.clone()).await.context("Failed to create metadata table")?;
    Self::create_sat_table(pool.clone()).await.context("Failed to create sat table")?;
    Self::create_content_table(pool.clone()).await.context("Failed to create content table")?;
    Self::create_edition_table(pool.clone()).await.context("Failed to create editions table")?;
    Self::create_editions_total_table(pool.clone()).await.context("Failed to create editions total table")?;
    Self::create_satributes_table(pool.clone()).await.context("Failed to create satributes table")?;
    Self::create_procedure_log(pool.clone()).await.context("Failed to create proc log")?;
    Self::create_edition_procedure(pool.clone()).await.context("Failed to create edition proc")?;
    Self::create_weights_procedure(pool.clone()).await.context("Failed to create weights proc")?;
    Self::create_edition_insert_trigger(pool.clone()).await.context("Failed to create edition trigger")?;
    Self::create_metadata_insert_trigger(pool.clone()).await.context("Failed to create metadata trigger")?;
    Ok(())
  }

  pub(crate) async fn create_metadata_table(pool: deadpool_postgres::Pool) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(
      r"CREATE TABLE IF NOT EXISTS ordinals (
        sequence_number bigint not null primary key,
        id varchar(80) not null,
        content_length bigint,
        content_type text,
        content_encoding text,
        genesis_fee bigint,
        genesis_height bigint,
        genesis_transaction varchar(80),
        pointer bigint,
        number bigint,          
        parent varchar(80),
        delegate varchar(80),
        metaprotocol text,
        embedded_metadata text,
        sat bigint,
        satributes varchar(30)[],
        charms smallint,
        timestamp bigint,
        sha256 varchar(64),
        text text,
        is_json boolean,
        is_maybe_json boolean,
        is_bitmap_style boolean,
        is_recursive boolean
      )").await?;
    conn.simple_query(r"
      CREATE INDEX IF NOT EXISTS index_metadata_id ON ordinals (id);
      CREATE INDEX IF NOT EXISTS index_metadata_number ON ordinals (number);
      CREATE INDEX IF NOT EXISTS index_metadata_block ON ordinals (genesis_height);
      CREATE INDEX IF NOT EXISTS index_metadata_sha256 ON ordinals (sha256);
      CREATE INDEX IF NOT EXISTS index_metadata_sat ON ordinals (sat);
      CREATE INDEX IF NOT EXISTS index_metadata_satributes on ordinals USING GIN (satributes);
      CREATE INDEX IF NOT EXISTS index_metadata_parent ON ordinals (parent);
      CREATE INDEX IF NOT EXISTS index_metadata_delegate ON ordinals (delegate);
      CREATE INDEX IF NOT EXISTS index_metadata_fee ON ordinals (genesis_fee);
      CREATE INDEX IF NOT EXISTS index_metadata_size ON ordinals (content_length);
      CREATE INDEX IF NOT EXISTS index_metadata_type ON ordinals (content_type);
      CREATE INDEX IF NOT EXISTS index_metadata_metaprotocol ON ordinals (metaprotocol);
      CREATE INDEX IF NOT EXISTS index_metadata_text ON ordinals USING GIN (to_tsvector('english', text));
    ").await?;
  
    Ok(())
  }
  
  pub(crate) async fn create_sat_table(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(r"
      CREATE TABLE IF NOT EXISTS sat (
      sat bigint not null primary key,
      satributes varchar(30)[],
      sat_decimal text,
      degree text,
      name text,
      block bigint,
      cycle bigint,
      epoch bigint,
      period bigint,
      third bigint,
      rarity varchar(20),
      percentile text,
      timestamp bigint
      )").await?;
    conn.simple_query(r"
      CREATE INDEX IF NOT EXISTS index_sat_block ON sat (block);
      CREATE INDEX IF NOT EXISTS index_sat_rarity ON sat (rarity);
      ").await?;
    Ok(())
  }
  
  pub(crate) async fn create_content_table(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(
      r"CREATE TABLE IF NOT EXISTS content (
        content_id bigint,
        sha256 varchar(64) NOT NULL PRIMARY KEY,
        content bytea,
        content_type text
      )").await?;
    conn.simple_query(r"
      CREATE INDEX IF NOT EXISTS index_content_content_id ON content (content_id);
      ").await?;
    Ok(())
  }
  
  pub(crate) async fn create_edition_table(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(
      r"CREATE TABLE IF NOT EXISTS editions (
          id varchar(80) not null primary key,
          number bigint,
          sequence_number bigint,
          sha256 varchar(64),
          edition bigint
      )").await?;
      conn.simple_query(r"
        CREATE INDEX IF NOT EXISTS index_editions_number ON editions (number);
        CREATE INDEX IF NOT EXISTS index_editions_sha256 ON editions (sha256);
      ").await?;
    Ok(())
  }
  
  pub(crate) async fn create_editions_total_table(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(
      r"CREATE TABLE IF NOT EXISTS editions_total (
          sha256 varchar(64) not null primary key,
          total bigint
      )").await?;
    Ok(())
  }
  
  pub(crate) async fn create_satributes_table(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(
      r"CREATE TABLE IF NOT EXISTS satributes (
        sat bigint not null,
        satribute varchar(30) not null,
        CONSTRAINT satribute_key PRIMARY KEY (sat, satribute)
      )").await?;
    conn.simple_query(r"
      CREATE INDEX IF NOT EXISTS index_satributes_sat ON satributes (sat);
      CREATE INDEX IF NOT EXISTS index_satributes_satribute ON satributes (satribute);
    ").await?;
    Ok(())
  }
  
  pub(crate) async fn bulk_insert<F, P, T>(
    pool: mysql_async::Pool,
    table: String,
    cols: Vec<String>,
    objects: Vec<T>,
    fun: F,
  ) -> mysql_async::Result<()>
  where
    F: Fn(&T) -> P,
    P: Into<Params>,
  {
    if objects.len() == 0 {
      return Ok(());
    }
    let mut stmt = format!("INSERT IGNORE INTO {} ({}) VALUES ", table, cols.join(","));
    let row = format!(
        "({}),",
        cols.iter()
            .map(|_| "?".to_string())
            .collect::<Vec<_>>()
            .join(",")
    );
    stmt.reserve(objects.len() * (cols.len() * 2 + 2));
    for _ in 0..objects.len() {
        stmt.push_str(&row);
    }
  
    // remove the trailing comma
    stmt.pop();
  
    let mut params = Vec::new();
  
    let bytes: Vec<Vec<u8>> = cols.iter().map(|s| s.clone().into_bytes()).collect();
    for o in objects.iter() {
        let named_params: mysql_async::Params = fun(o).into();
        let positional_params = named_params.into_positional(bytes.as_slice())?;
        if let mysql_async::Params::Positional(new_params) = positional_params {
            for param in new_params {
                params.push(param);
            }
        }
    }
  
    let mut conn = pool.get_conn().await?;
    let mut tx = conn.start_transaction(TxOpts::default()).await.unwrap();
    let result = tx.exec_drop(stmt, params).await;
    tx.commit().await?;
    result
  }

  pub(crate) async fn bulk_insert_update<F, P, T>(
    pool: mysql_async::Pool,
    table: String,
    cols: Vec<String>,
    update_cols: Vec<String>,
    objects: Vec<T>,
    fun: F,
  ) -> mysql_async::Result<()>
  where
    F: Fn(&T) -> P,
    P: Into<Params>,
  {
    if objects.len() == 0 {
      return Ok(());
    }
    
    let mut stmt = format!("INSERT INTO {} ({}) VALUES ", table, cols.join(","));
    let row = format!(
        "({}),",
        cols.iter()
            .map(|_| "?".to_string())
            .collect::<Vec<_>>()
            .join(",")
    );
    stmt.reserve(objects.len() * (cols.len() * 2 + 2));
    for _ in 0..objects.len() {
        stmt.push_str(&row);
    }
  
    // remove the trailing comma
    stmt.pop();
  
    // ON DUPLICATE KEY UPDATE
    let formatted_string = update_cols
      .iter()
      .map(|field| {
        format!("{}=VALUES({})", field, field)
      })
      .collect::<Vec<_>>()
      .join(",");
    let duplicate_key_stmt = format!(" ON DUPLICATE KEY UPDATE {}", formatted_string);
    stmt.push_str(&duplicate_key_stmt);
  
    let mut params = Vec::new();
  
    let bytes: Vec<Vec<u8>> = cols.iter().map(|s| s.clone().into_bytes()).collect();
    for o in objects.iter() {
        let named_params: mysql_async::Params = fun(o).into();
        let positional_params = named_params.into_positional(bytes.as_slice())?;
        if let mysql_async::Params::Positional(new_params) = positional_params {
            for param in new_params {
                params.push(param);
            }
        }
    }
    let mut conn = pool.get_conn().await?;
    let result = conn.exec_drop(stmt, params).await;
    result
  }

  pub(crate) async fn mass_insert_metadata_and_editions(pool: mysql_async::Pool, metadata_vec: Vec<Metadata>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut conn = Self::get_conn(pool.clone()).await?;
    conn.query_drop("SET SQL_LOG_BIN = 0").await?;
    conn.query_drop("START TRANSACTION").await?;
    Self::mass_insert_metadata(&mut conn, metadata_vec.clone()).await?;
    Self::mass_insert_editions(&mut conn, metadata_vec).await?;
    conn.query_drop("COMMIT").await?;
    Ok(())
  }

  async fn bulk_insert_metadata(tx: &deadpool_postgres::Transaction<'_>, data: Vec<Metadata>) -> anyhow::Result<()> {
    //tx.simple_query("CREATE TEMP TABLE inserts_ordinals ON COMMIT DROP AS TABLE ordinals WITH NO DATA").await?;
    let copy_stm = r#"COPY ordinals (
      sequence_number, 
      id, 
      content_length, 
      content_type, 
      content_encoding, 
      genesis_fee, 
      genesis_height, 
      genesis_transaction, 
      pointer, 
      number, 
      parent, 
      delegate, 
      metaprotocol, 
      embedded_metadata, 
      sat,
      satributes,
      charms, 
      timestamp, 
      sha256, 
      text, 
      is_json, 
      is_maybe_json, 
      is_bitmap_style, 
      is_recursive) FROM STDIN BINARY"#;
    let col_types = vec![
      Type::INT8,
      Type::VARCHAR,
      Type::INT8,
      Type::TEXT,
      Type::TEXT,
      Type::INT8,
      Type::INT8,
      Type::VARCHAR,
      Type::INT8,
      Type::INT8,
      Type::VARCHAR,
      Type::VARCHAR,
      Type::TEXT,
      Type::TEXT,
      Type::INT8,
      Type::VARCHAR_ARRAY,
      Type::INT2,
      Type::INT8,
      Type::VARCHAR,
      Type::TEXT,
      Type::BOOL,
      Type::BOOL,
      Type::BOOL,
      Type::BOOL
    ];
    let sink = tx.copy_in(copy_stm).await?;
    let writer = BinaryCopyInWriter::new(sink, &col_types);
    pin_mut!(writer);
    for m in data {
      let mut row: Vec<&'_ (dyn ToSql + Sync)> = Vec::new();
      row.push(&m.sequence_number);
      row.push(&m.id);
      row.push(&m.content_length);
      let clean_type = &m.content_type.map(|s| s.replace("\0", ""));
      row.push(clean_type);
      let clean_encoding = &m.content_encoding.map(|s| s.replace("\0", ""));
      row.push(clean_encoding);
      row.push(&m.genesis_fee);
      row.push(&m.genesis_height);
      row.push(&m.genesis_transaction);
      row.push(&m.pointer);
      row.push(&m.number);
      row.push(&m.parent);
      row.push(&m.delegate);
      let clean_metaprotocol = &m.metaprotocol.map(|s| s.replace("\0", ""));
      row.push(clean_metaprotocol);
      let clean_metadata = &m.embedded_metadata.map(|s| s.replace("\0", ""));
      row.push(clean_metadata);
      row.push(&m.sat);
      row.push(&m.satributes);
      row.push(&m.charms);
      row.push(&m.timestamp);
      row.push(&m.sha256);
      let clean_text = &m.text.map(|s| s.replace("\0", ""));
      row.push(clean_text);
      row.push(&m.is_json);
      row.push(&m.is_maybe_json);
      row.push(&m.is_bitmap_style);
      row.push(&m.is_recursive);
      writer.as_mut().write(&row).await?;
    }
  
    let x = writer.finish().await?;
    //println!("Finished writing metadata: {:?}", x);
    //tx.simple_query("INSERT INTO ordinals SELECT * FROM inserts_ordinals ON CONFLICT DO NOTHING").await?;
    Ok(())
  }

  pub(crate) async fn mass_insert_metadata(conn: &mut mysql_async::Conn, metadata_vec: Vec<Metadata>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut wtr = WriterBuilder::new()
      .has_headers(false)
      .from_writer(vec![]);
    for metadata in metadata_vec.iter() {
      wtr.serialize(metadata).unwrap();
    }
    let inner = wtr.into_inner().unwrap();
    //println!("{:?}", String::from_utf8(inner.clone()));
    let bytes = Bytes::from(inner);
    // We are going to call `LOAD DATA LOCAL` so let's setup a one-time handler.
    conn.set_infile_handler(async move {
      // We need to return a stream of `io::Result<Bytes>`
      Ok(futures::stream::iter([bytes]).map(Ok).boxed())
    });
  
    let result: Option<mysql_async::Value> = conn.query_first(r#"LOAD DATA LOCAL INFILE 'whatever'
      REPLACE INTO TABLE `ordinals`
      FIELDS TERMINATED BY ',' ENCLOSED BY '\"' ESCAPED BY '\"'
      LINES TERMINATED BY '\n'
      (sequence_number, id, @vcontent_length, @vcontent_type, @vcontent_encoding, genesis_fee, genesis_height, genesis_transaction, @vpointer, number, @vparent, @vdelegate, @vmetaprotocol, @vembedded_metadata, @vsat, @vcharms, timestamp, @vsha256, text, @vis_json, @vis_maybe_json, @vis_bitmap_style, @vis_recursive)
      SET
      content_length = nullif(@vcontent_length, ''),
      content_type = nullif(@vcontent_type, ''),
      content_encoding = nullif(@vcontent_encoding, ''),
      pointer = nullif(@vpointer, ''),
      parent = nullif(@vparent, ''),
      delegate = nullif(@vdelegate, ''),
      metaprotocol = nullif(@vmetaprotocol, ''),
      embedded_metadata = nullif(@vembedded_metadata, ''),
      sat = nullif(@vsat, ''),
      charms = nullif(@vcharms, ''),
      sha256 = nullif(@vsha256, ''),
      is_json = (@vis_json = 'true'),
      is_maybe_json = (@vis_maybe_json = 'true'),
      is_bitmap_style = (@vis_bitmap_style = 'true'),
      is_recursive = (@vis_recursive = 'true')
      "#).await?;
    
    Ok(())
  }

  async fn bulk_insert_sat_metadata(tx: &deadpool_postgres::Transaction<'_>, data: Vec<SatMetadata>) -> anyhow::Result<()> {
    tx.simple_query("CREATE TEMP TABLE inserts_sat ON COMMIT DROP AS TABLE sat WITH NO DATA").await?;
    let copy_stm = r#"COPY inserts_sat (
      sat,
      satributes,
      sat_decimal,
      degree,
      name,
      block,
      cycle,
      epoch,
      period,
      third,
      rarity,
      percentile,
      timestamp) FROM STDIN BINARY"#;
    let col_types = vec![
      Type::INT8,
      Type::VARCHAR_ARRAY,
      Type::TEXT,
      Type::TEXT,
      Type::TEXT,
      Type::INT8,
      Type::INT8,
      Type::INT8,
      Type::INT8,
      Type::INT8,
      Type::TEXT,
      Type::TEXT,
      Type::INT8
    ];
    let sink = tx.copy_in(copy_stm).await?;
    let writer = BinaryCopyInWriter::new(sink, &col_types);
    pin_mut!(writer);
    for m in data {
      let mut row: Vec<&'_ (dyn ToSql + Sync)> = Vec::new();
      row.push(&m.sat);
      row.push(&m.satributes);
      row.push(&m.decimal);
      row.push(&m.degree);
      row.push(&m.name);
      row.push(&m.block);
      row.push(&m.cycle);
      row.push(&m.epoch);
      row.push(&m.period);
      row.push(&m.third);
      row.push(&m.rarity);
      row.push(&m.percentile);
      row.push(&m.timestamp);
      writer.as_mut().write(&row).await?;
    }  
    writer.finish().await?;
    tx.simple_query("INSERT INTO sat SELECT * FROM inserts_sat ON CONFLICT DO NOTHING").await?;
    Ok(())
  }

  pub(crate) async fn mass_insert_sat_metadata(pool: mysql_async::Pool, metadata_vec: Vec<SatMetadata>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut conn = Self::get_conn(pool).await?;
    conn.query_drop("SET SQL_LOG_BIN = 0").await?;

    let mut wtr = WriterBuilder::new()
      .has_headers(false)
      .from_writer(vec![]);
    for metadata in metadata_vec.iter() {
      wtr.serialize(metadata).unwrap();
    }
    let bytes = Bytes::from(wtr.into_inner().unwrap());
    // We are going to call `LOAD DATA LOCAL` so let's setup a one-time handler.
    conn.set_infile_handler(async move {
      // We need to return a stream of `io::Result<Bytes>`
      Ok(futures::stream::iter([bytes]).map(Ok).boxed())
    });
  
    let result: Option<mysql_async::Value> = conn.query_first(r#"LOAD DATA LOCAL INFILE 'whatever'
      REPLACE INTO TABLE `sat`
      FIELDS TERMINATED BY ',' ENCLOSED BY '\"' ESCAPED BY '\"'
      LINES TERMINATED BY '\n'
      (sat, sat_decimal, degree, name, block, cycle, epoch, period, offset, rarity, percentile, timestamp)
      "#).await?;
    Ok(())
  }

  async fn bulk_insert_content(tx: &deadpool_postgres::Transaction<'_>, data: Vec<(i64, ContentBlob)>) -> anyhow::Result<()> {
    tx.simple_query("CREATE TEMP TABLE inserts_content ON COMMIT DROP AS TABLE content WITH NO DATA").await?;
    let copy_stm = r#"COPY inserts_content (
      content_id,
      sha256, 
      content, 
      content_type) FROM STDIN BINARY"#;
    let col_types = vec![
      Type::INT8,
      Type::VARCHAR,
      Type::BYTEA,
      Type::TEXT
    ];
    let sink = tx.copy_in(copy_stm).await?;
    let writer = BinaryCopyInWriter::new(sink, &col_types);
    pin_mut!(writer);
    for (sequence_number, content) in data {
      let mut row: Vec<&'_ (dyn ToSql + Sync)> = Vec::new();
      row.push(&sequence_number);
      row.push(&content.sha256);
      row.push(&content.content);
      row.push(&content.content_type);
      writer.as_mut().write(&row).await?;
    }
    writer.finish().await?;
    tx.simple_query("INSERT INTO content SELECT content_id, sha256, content, content_type FROM inserts_content ON CONFLICT DO NOTHING").await?;
    Ok(())
  }

  pub(crate) async fn mass_insert_content(pool: mysql_async::Pool, content_vec: Vec<ContentBlob>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut conn = Self::get_conn(pool).await?;
    conn.query_drop("SET SQL_LOG_BIN = 0").await?;
    let mut wtr = WriterBuilder::new()
      .has_headers(false)
      .from_writer(vec![]);

    for content in content_vec.iter() {
      wtr.write_field(content.sha256.clone())?;
      wtr.write_field(hex::encode(&content.content))?;
      wtr.write_field(content.content_type.clone())?;
      wtr.write_record(None::<&[u8]>)?;
    }
    let bytes = Bytes::from(wtr.into_inner().unwrap());
    // We are going to call `LOAD DATA LOCAL` so let's setup a one-time handler.
    conn.set_infile_handler(async move {
      // We need to return a stream of `io::Result<Bytes>`
      Ok(futures::stream::iter([bytes]).map(Ok).boxed())
    });
  
    let result: Option<mysql_async::Value> = conn.query_first(r#"LOAD DATA LOCAL INFILE 'whatever'
      REPLACE INTO TABLE `content`
      FIELDS TERMINATED BY ',' ENCLOSED BY '\"' ESCAPED BY '\"'
      LINES TERMINATED BY '\n'
      (sha256, @vcontent, content_type)
      SET
      content = UNHEX(@vcontent)
      "#).await?;
    Ok(())
  }

  pub(crate) async fn bulk_insert_editions(tx: &deadpool_postgres::Transaction<'_>, metadata_vec: Vec<Metadata>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tx.simple_query("CREATE TEMP TABLE inserts_editions ON COMMIT DROP AS TABLE editions WITH NO DATA").await?;
    let copy_stm = r#"COPY inserts_editions (      
      id,
      number,
      sequence_number,
      sha256, 
      edition) FROM STDIN BINARY"#;
    let col_types = vec![
      Type::VARCHAR,
      Type::INT8,
      Type::INT8,
      Type::VARCHAR,
      Type::INT8
    ];
    let sink = tx.copy_in(copy_stm).await?;
    let writer = BinaryCopyInWriter::new(sink, &col_types);
    pin_mut!(writer);
    let edition: i64 = 0;
    for m in metadata_vec {
      let mut row: Vec<&'_ (dyn ToSql + Sync)> = Vec::new();
      row.push(&m.id);
      row.push(&m.number);
      row.push(&m.sequence_number);
      row.push(&m.sha256);
      row.push(&edition);
      writer.as_mut().write(&row).await?;
    }
    writer.finish().await?;
    tx.simple_query("INSERT INTO editions SELECT id, number, sequence_number, coalesce(sha256,''), edition FROM inserts_editions ON CONFLICT DO NOTHING").await?;
    Ok(())
  }

  pub(crate) async fn mass_insert_editions(conn: &mut mysql_async::Conn, metadata_vec: Vec<Metadata>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut wtr = WriterBuilder::new()
      .has_headers(false)
      .from_writer(vec![]);
    for metadata in metadata_vec.iter() {
      wtr.write_field(metadata.id.clone())?;
      wtr.write_field(metadata.number.to_string())?;
      wtr.write_field(metadata.sequence_number.to_string())?;
      wtr.write_field(metadata.sha256.clone().unwrap_or_else(|| "".to_string()))?;
      wtr.write_record(None::<&[u8]>)?;
    }
    let inner = wtr.into_inner().unwrap();
    //println!("{:?}", String::from_utf8(inner.clone()));
    let bytes = Bytes::from(inner);
    // We are going to call `LOAD DATA LOCAL` so let's setup a one-time handler.
    conn.set_infile_handler(async move {
      // We need to return a stream of `io::Result<Bytes>`
      Ok(futures::stream::iter([bytes]).map(Ok).boxed())
    });
  
    let result: Option<mysql_async::Value> = conn.query_first(r#"LOAD DATA LOCAL INFILE 'whatever'
      REPLACE INTO TABLE `editions`
      FIELDS TERMINATED BY ',' ENCLOSED BY '\"' ESCAPED BY '\"'
      LINES TERMINATED BY '\n'
      (id, number, sequence_number, @vsha256)
      SET
      sha256 = nullif(@vsha256, ''),
      edition = 0
      "#).await?;
    
    Ok(())
  }

  async fn bulk_insert_satributes(tx: &deadpool_postgres::Transaction<'_>, data: Vec<Satribute>) -> anyhow::Result<()> {
    tx.simple_query("CREATE TEMP TABLE inserts_satributes ON COMMIT DROP AS TABLE satributes WITH NO DATA").await?;
    let copy_stm = r#"COPY inserts_satributes (
      sat,
      satribute) FROM STDIN BINARY"#;
    let col_types = vec![
      Type::INT8,
      Type::VARCHAR
    ];
    let sink = tx.copy_in(copy_stm).await?;
    let writer = BinaryCopyInWriter::new(sink, &col_types);
    pin_mut!(writer);
    for m in data {
      let mut row: Vec<&'_ (dyn ToSql + Sync)> = Vec::new();
      row.push(&m.sat);
      row.push(&m.satribute);
      writer.as_mut().write(&row).await?;
    }  
    writer.finish().await?;
    tx.simple_query("INSERT INTO satributes SELECT * FROM inserts_satributes ON CONFLICT DO NOTHING").await?;
    Ok(())
  }

  pub(crate) async fn mass_insert_satributes(pool: mysql_async::Pool, satribute_vec: Vec<Satribute>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut conn = Self::get_conn(pool).await?;
    conn.query_drop("SET SQL_LOG_BIN = 0").await?;
    let mut wtr = WriterBuilder::new()
      .has_headers(false)
      .from_writer(vec![]);
    for satribute in satribute_vec.iter() {
      wtr.serialize(satribute).unwrap();
    }
    let bytes = Bytes::from(wtr.into_inner().unwrap());
    // We are going to call `LOAD DATA LOCAL` so let's setup a one-time handler.
    conn.set_infile_handler(async move {
      // We need to return a stream of `io::Result<Bytes>`
      Ok(futures::stream::iter([bytes]).map(Ok).boxed())
    });
  
    let result: Option<mysql_async::Value> = conn.query_first(r#"LOAD DATA LOCAL INFILE 'whatever'
      REPLACE INTO TABLE `satributes`
      FIELDS TERMINATED BY ',' ENCLOSED BY '\"' ESCAPED BY '\"'
      LINES TERMINATED BY '\n'
      (sat, satribute)
      "#).await?;
    Ok(())
  }

  pub(crate) async fn get_last_number(pool: deadpool_postgres::Pool<>) -> anyhow::Result<i64> {
    let conn = pool.get().await?;
    let row = conn.query_one("SELECT max(sequence_number) from ordinals", &[]).await?;
    let last_number: Option<i64> = row.get(0);
    Ok(last_number.unwrap_or(-1))
  }

  pub(crate) async fn get_needed_sequence_numbers(status_vector: Arc<Mutex<Vec<SequenceNumberStatus>>>) -> Vec<u64> {
    let mut status_vector = status_vector.lock().await;
    let largest_number_in_vec = status_vector.iter().max_by_key(|status| status.sequence_number).unwrap().sequence_number;
    let mut needed_inscription_numbers: Vec<u64> = Vec::new();
    //Find start of needed numbers
    let mut pending_count=0;
    let mut unknown_count=0;
    let mut error_count=0;
    let mut not_found_count=0;
    let mut success_count=0;
    for status in status_vector.iter() {
      if status.status == "UNKNOWN" || status.status == "ERROR" || status.status == "NOT_FOUND" {
        needed_inscription_numbers.push(status.sequence_number);
      }
      if status.status == "PENDING" {
        pending_count = pending_count + 1;
      }
      if status.status == "UNKNOWN" {
        unknown_count = unknown_count + 1;
      }
      if status.status == "ERROR" || status.status == "ERROR_LOCKED"  {
        error_count = error_count + 1;
      }
      if status.status == "NOT_FOUND" || status.status == "NOT_FOUND_LOCKED" {
        not_found_count = not_found_count + 1;
      }
      if status.status == "SUCCESS" {
        success_count = success_count + 1;
      }
    }
    log::info!("Pending: {}, Unknown: {}, Error: {}, Not Found: {}, Success: {}", pending_count, unknown_count, error_count, not_found_count, success_count);
    //Fill in needed numbers
    let mut needed_length = needed_inscription_numbers.len();
    needed_inscription_numbers.sort();
    if needed_length < INDEX_BATCH_SIZE {
      let mut i = 0;
      while needed_length < INDEX_BATCH_SIZE {        
        i = i + 1;
        needed_inscription_numbers.push(largest_number_in_vec + i);
        needed_length = needed_inscription_numbers.len();
      }
    } else {
      needed_inscription_numbers = needed_inscription_numbers[0..INDEX_BATCH_SIZE].to_vec();
    }
    //Mark as pending
    for number in needed_inscription_numbers.clone() {
      match status_vector.iter_mut().find(|status| status.sequence_number == number) {
        Some(status) => {
          status.status = "PENDING".to_string();
        },
        None => {
          let status = SequenceNumberStatus{
            sequence_number: number,
            status: "PENDING".to_string(),
          };
          status_vector.push(status);
        }
      };
    }
    //Remove successfully processed numbers from vector
    status_vector.retain(|status| status.status != "SUCCESS");
    needed_inscription_numbers
  }

  pub(crate) async fn print_index_timings(timings: Arc<Mutex<Vec<IndexerTimings>>>, n_threads: u32) {
    let mut locked_timings = timings.lock().await;
    // sort & remove incomplete entries    
    locked_timings.retain(|e| e.inscription_start + INDEX_BATCH_SIZE as u64 == e.inscription_end);
    locked_timings.sort_by(|a, b| a.inscription_start.cmp(&b.inscription_start));
    if locked_timings.len() < 1 {
      return;
    }
    //First get the relevant entries
    let mut relevant_timings: Vec<IndexerTimings> = Vec::new();
    let mut last = locked_timings.last().unwrap().inscription_start + INDEX_BATCH_SIZE as u64;
    for timing in locked_timings.iter().rev() {
      if timing.inscription_start == last - INDEX_BATCH_SIZE as u64 {
        relevant_timings.push(timing.clone());
        if relevant_timings.len() == n_threads as usize {
          break;
        }
      } else {
        relevant_timings = Vec::new();
        relevant_timings.push(timing.clone());
      }      
      last = timing.inscription_start;
    }
    if relevant_timings.len() < n_threads as usize {
      return;
    }    
    relevant_timings.sort_by(|a, b| a.inscription_start.cmp(&b.inscription_start));    
    let mut queueing_total = Duration::new(0,0);
    let mut acquire_permit_total = Duration::new(0,0);
    let mut get_numbers_total = Duration::new(0,0);
    let mut get_id_total = Duration::new(0,0);
    let mut get_inscription_total = Duration::new(0,0);
    let mut upload_content_total = Duration::new(0,0);
    let mut get_metadata_total = Duration::new(0,0);
    let mut retrieval_total = Duration::new(0,0);
    let mut insertion_total = Duration::new(0,0);
    let mut metadata_insertion_total = Duration::new(0,0);
    let mut sat_insertion_total = Duration::new(0,0);
    let mut edition_insertion_total = Duration::new(0,0);
    let mut content_insertion_total = Duration::new(0,0);
    let mut locking_total = Duration::new(0,0);
    let mut last_start = relevant_timings.first().unwrap().acquire_permit_start;
    for timing in relevant_timings.iter() {
      queueing_total = queueing_total + timing.acquire_permit_start.duration_since(last_start);
      acquire_permit_total = acquire_permit_total + timing.acquire_permit_end.duration_since(timing.acquire_permit_start);
      get_numbers_total = get_numbers_total + timing.get_numbers_end.duration_since(timing.get_numbers_start);
      get_id_total = get_id_total + timing.get_id_end.duration_since(timing.get_id_start);
      get_inscription_total = get_inscription_total + timing.get_inscription_end.duration_since(timing.get_inscription_start);
      upload_content_total = upload_content_total + timing.upload_content_end.duration_since(timing.upload_content_start);
      get_metadata_total = get_metadata_total + timing.get_metadata_end.duration_since(timing.get_metadata_start);
      retrieval_total = retrieval_total + timing.retrieval;
      insertion_total = insertion_total + timing.insertion;
      metadata_insertion_total = metadata_insertion_total + timing.metadata_insertion;
      sat_insertion_total = sat_insertion_total + timing.sat_insertion;
      edition_insertion_total = edition_insertion_total + timing.edition_insertion;
      content_insertion_total = content_insertion_total + timing.content_insertion;
      locking_total = locking_total + timing.locking;
      last_start = timing.acquire_permit_start;
    }
    let count = relevant_timings.last().unwrap().inscription_end - relevant_timings.first().unwrap().inscription_start+1;
    let total_time = relevant_timings.last().unwrap().get_metadata_end.duration_since(relevant_timings.first().unwrap().get_numbers_start);
    log::info!("Inscriptions {}-{}", relevant_timings.first().unwrap().inscription_start, relevant_timings.last().unwrap().inscription_end);
    log::info!("Total time: {:?}, avg per inscription: {:?}", total_time, total_time/count as u32);
    log::info!("Queueing time avg per thread: {:?}", queueing_total/n_threads); //9 because the first one doesn't have a recorded queueing time
    log::info!("Acquiring Permit time avg per thread: {:?}", acquire_permit_total/n_threads); //should be similar to queueing time
    log::info!("Get numbers time avg per thread: {:?}", get_numbers_total/n_threads);
    log::info!("Get id time avg per thread: {:?}", get_id_total/n_threads);
    log::info!("Get inscription time avg per thread: {:?}", get_inscription_total/n_threads);
    log::info!("Upload content time avg per thread: {:?}", upload_content_total/n_threads);
    log::info!("Get metadata time avg per thread: {:?}", get_metadata_total/n_threads);
    log::info!("--Retrieval time avg per thread: {:?}", retrieval_total/n_threads);
    log::info!("--Insertion time avg per thread: {:?}", insertion_total/n_threads);
    log::info!("--Metadata Insertion time avg per thread: {:?}", metadata_insertion_total/n_threads);
    log::info!("--Sat Insertion time avg per thread: {:?}", sat_insertion_total/n_threads);
    log::info!("--Satribute Insertion time avg per thread: {:?}", edition_insertion_total/n_threads);
    log::info!("--Content Insertion time avg per thread: {:?}", content_insertion_total/n_threads);
    log::info!("--Locking time avg per thread: {:?}", locking_total/n_threads);

    //Remove printed timings
    let to_remove = BTreeSet::from_iter(relevant_timings);
    locked_timings.retain(|e| !to_remove.contains(e));

  }

  //Address Indexer Helper functions
  pub(crate) async fn create_transfers_table(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(
      r"CREATE TABLE IF NOT EXISTS transfers (
        id varchar(80) not null,
        block_number bigint not null,
        block_timestamp bigint,
        satpoint varchar(100) not null,
        transaction text,
        vout int,
        satpoint_offset bigint,
        address text,
        is_genesis boolean,
        PRIMARY KEY (id, block_number, satpoint)
      )").await?;
    conn.simple_query(r"
      CREATE INDEX IF NOT EXISTS index_transfers_id ON transfers (id);
      CREATE INDEX IF NOT EXISTS index_transfers_block ON transfers (block_number);
    ").await?;
    Ok(())
  }
  pub(crate) async fn bulk_insert_transfers(tx: &deadpool_postgres::Transaction<'_>, transfer_vec: Vec<Transfer>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let copy_stm = r#"COPY transfers (
      id,
      block_number,
      block_timestamp,
      satpoint,
      transaction,
      vout,
      satpoint_offset,
      address,
      is_genesis) FROM STDIN BINARY"#;
    let col_types = vec![
      Type::VARCHAR,
      Type::INT8,
      Type::INT8,
      Type::TEXT,
      Type::TEXT,
      Type::INT4,
      Type::INT8,
      Type::TEXT,
      Type::BOOL
    ];
    let sink = tx.copy_in(copy_stm).await?;
    let writer = BinaryCopyInWriter::new(sink, &col_types);
    pin_mut!(writer);
    for m in transfer_vec {
      let mut row: Vec<&'_ (dyn ToSql + Sync)> = Vec::new();
      row.push(&m.id);
      row.push(&m.block_number);
      row.push(&m.block_timestamp);
      row.push(&m.satpoint);
      row.push(&m.transaction);
      row.push(&m.vout);
      row.push(&m.offset);
      row.push(&m.address);
      row.push(&m.is_genesis);
      writer.as_mut().write(&row).await?;
    }
    writer.finish().await?;
    Ok(())
  }

  pub(crate) async fn mass_insert_transfers(pool: mysql_async::Pool, transfer_vec: Vec<Transfer>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for chunk in transfer_vec.chunks(5000) {
      let mut conn = Self::get_conn(pool.clone()).await?;  
      conn.query_drop("SET SQL_LOG_BIN = 0").await?;
      let mut wtr = WriterBuilder::new()
        .has_headers(false)
        .from_writer(vec![]);
      for transfer in chunk.iter() {
        wtr.serialize(transfer).unwrap();
      }
      let inner = wtr.into_inner().unwrap();
      let bytes = Bytes::from(inner);
      // We are going to call `LOAD DATA LOCAL` so let's setup a one-time handler.
      conn.set_infile_handler(async move {
        // We need to return a stream of `io::Result<Bytes>`
        Ok(futures::stream::iter([bytes]).map(Ok).boxed())
      });
    
      let result: Option<mysql_async::Value> = conn.query_first(r#"LOAD DATA LOCAL INFILE 'whatever'
        REPLACE INTO TABLE `transfers`
        FIELDS TERMINATED BY ',' ENCLOSED BY '\"' ESCAPED BY '\"'
        LINES TERMINATED BY '\n'
        (id, block_number, block_timestamp, satpoint, transaction, vout, offset, address, @vis_genesis)
        SET is_genesis = (@vis_genesis = 'true')
        "#).await?;
    }
    Ok(())
  }

  pub(crate) async fn create_address_table(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(
      r"CREATE TABLE IF NOT EXISTS addresses (
        id varchar(80) not null primary key,
        block_number bigint not null,
        block_timestamp bigint,
        satpoint varchar(100),
        transaction text,
        vout int,
        satpoint_offset bigint,
        address varchar(100),
        is_genesis boolean
      )").await?;
    conn.simple_query(r"
      CREATE INDEX IF NOT EXISTS index_address ON addresses (address);
    ").await?;
    Ok(())
  }
  
  pub(crate) async fn bulk_insert_addresses(tx: &deadpool_postgres::Transaction<'_>, mut transfer_vec: Vec<Transfer>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    //ON CONFLICT DO UPDATE command cannot affect row a second time, so we reverse & dedup (effectively keeping the last transfer in block)
    transfer_vec.reverse();
    transfer_vec.dedup_by(|a, b| a.id == b.id);
    tx.simple_query("CREATE TEMP TABLE inserts_addresses ON COMMIT DROP AS TABLE addresses WITH NO DATA").await?;
    let copy_stm = r#"COPY inserts_addresses (
      id,
      block_number,
      block_timestamp,
      satpoint,
      transaction,
      vout,
      satpoint_offset,
      address,
      is_genesis) FROM STDIN BINARY"#;
    let col_types = vec![
      Type::VARCHAR,
      Type::INT8,
      Type::INT8,
      Type::TEXT,
      Type::TEXT,
      Type::INT4,
      Type::INT8,
      Type::VARCHAR,
      Type::BOOL
    ];
    let sink = tx.copy_in(copy_stm).await?;
    let writer = BinaryCopyInWriter::new(sink, &col_types);
    pin_mut!(writer);
    for m in transfer_vec {
      let mut row: Vec<&'_ (dyn ToSql + Sync)> = Vec::new();
      row.push(&m.id);
      row.push(&m.block_number);
      row.push(&m.block_timestamp);
      row.push(&m.satpoint);
      row.push(&m.transaction);
      row.push(&m.vout);
      row.push(&m.offset);
      row.push(&m.address);
      row.push(&m.is_genesis);
      writer.as_mut().write(&row).await?;
    }
    writer.finish().await?;
    tx.simple_query("INSERT INTO addresses SELECT * FROM inserts_addresses ON CONFLICT (id) DO UPDATE SET 
      block_number = EXCLUDED.block_number, 
      block_timestamp = EXCLUDED.block_timestamp,
      satpoint = EXCLUDED.satpoint,
      transaction = EXCLUDED.transaction,
      vout = EXCLUDED.vout,
      satpoint_offset = EXCLUDED.satpoint_offset,
      address = EXCLUDED.address,
      is_genesis = EXCLUDED.is_genesis").await?;
    Ok(())
  }

  pub(crate) async fn mass_insert_addresses(pool: mysql_async::Pool, transfer_vec: Vec<Transfer>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for chunk in transfer_vec.chunks(5000) {
      let mut conn = Self::get_conn(pool.clone()).await?;
      conn.query_drop("SET SQL_LOG_BIN = 0").await?;
      let mut wtr = WriterBuilder::new()
        .has_headers(false)
        .from_writer(vec![]);
      for transfer in chunk.iter() {
        wtr.serialize(transfer).unwrap();
      }
      let inner = wtr.into_inner().unwrap();
      let bytes = Bytes::from(inner);
      // We are going to call `LOAD DATA LOCAL` so let's setup a one-time handler.
      conn.set_infile_handler(async move {
        // We need to return a stream of `io::Result<Bytes>`
        Ok(futures::stream::iter([bytes]).map(Ok).boxed())
      });
    
      let result: Option<mysql_async::Value> = conn.query_first(r#"LOAD DATA LOCAL INFILE 'whatever'
        REPLACE INTO TABLE `addresses`
        FIELDS TERMINATED BY ',' ENCLOSED BY '\"' ESCAPED BY '\"'
        LINES TERMINATED BY '\n'
        (id, block_number, block_timestamp, satpoint, transaction, vout, offset, address, @vis_genesis)
        SET is_genesis = (@vis_genesis = 'true')
        "#).await?;
    }    
    Ok(())
  }

  pub(crate) async fn get_start_block(pool: deadpool) -> Result<u32, Box<dyn std::error::Error>> {
    let conn = pool.get().await?;
    let row = conn.query_one("SELECT max(block_number) from blockheights", &[]).await;
    let last_block = match row {
      Ok(row) => {
        let last_block: Option<i64> = row.get(0);
        last_block.unwrap_or(-1)
      },
      Err(_) => -1
    };
    Ok((last_block + 1) as u32)
  }

  pub(crate) async fn bulk_insert_blockheights(tx: &deadpool_postgres::Transaction<'_>, blockheights: Vec<BlockHeight>) -> Result<(), Box<dyn std::error::Error>> {
    let copy_stm = r#"COPY blockheights (
      block_number,
      block_timestamp) FROM STDIN BINARY"#;
    let col_types = vec![
      Type::INT8,
      Type::INT8
    ];
    let sink = tx.copy_in(copy_stm).await?;
    let writer = BinaryCopyInWriter::new(sink, &col_types);
    pin_mut!(writer);
    for m in blockheights {
      let mut row: Vec<&'_ (dyn ToSql + Sync)> = Vec::new();
      row.push(&m.block_number);
      row.push(&m.block_timestamp);
      writer.as_mut().write(&row).await?;
    }
    writer.finish().await?;
    Ok(())
  }

  pub(crate) async fn mass_insert_blockheights(pool: mysql_async::Pool, blockheights: Vec<BlockHeight>) -> Result<(), Box<dyn std::error::Error>> {
    let mut conn = Self::get_conn(pool).await?;
    let mut wtr = WriterBuilder::new()
      .has_headers(false)
      .from_writer(vec![]);
    for blockheight in blockheights.iter() {
      wtr.serialize(blockheight).unwrap();
    }
    let inner = wtr.into_inner().unwrap();
    let bytes = Bytes::from(inner);
    // We are going to call `LOAD DATA LOCAL` so let's setup a one-time handler.
    conn.set_infile_handler(async move {
      // We need to return a stream of `io::Result<Bytes>`
      Ok(futures::stream::iter([bytes]).map(Ok).boxed())
    });
  
    let result: Option<mysql_async::Value> = conn.query_first(r#"LOAD DATA LOCAL INFILE 'whatever'
      REPLACE INTO TABLE `blockheights`
      FIELDS TERMINATED BY ',' ENCLOSED BY '\"' ESCAPED BY '\"'
      LINES TERMINATED BY '\n'
      (block_number, block_timestamp)
      "#).await?;
    Ok(())
  }

  pub(crate) async fn create_blockheight_table(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(
      r"CREATE TABLE IF NOT EXISTS blockheights (
        block_number bigint not null primary key,
        block_timestamp bigint not null
      )").await?;
    Ok(())
  }
  
  //Server api functions
  async fn root() -> &'static str {
"If Bitcoin is to change the culture of money, it needs to be cool. Ordinals was the missing piece. The path to $1m is preordained"
  }

  async fn home(State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let content_blob = match Self::get_ordinal_content(server_config.deadpool,  "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799i0".to_string()).await {
      Ok(content_blob) => content_blob,
      Err(error) => {
        log::warn!("Error getting /home: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving 6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799i0"),
        ).into_response();
      }
    };
    let bytes = content_blob.content;
    let content_type = content_blob.content_type;
    (
        ([(axum::http::header::CONTENT_TYPE, content_type)]),
        bytes,
    ).into_response()
  }

  async fn set_header<B>(response: Response<B>) -> Response<B> {
    //response.headers_mut().insert("cache-control", "public, max-age=31536000, immutable".parse().unwrap());
    response
  }

  async fn inscription(Path(inscription_id): Path<InscriptionId>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let content_blob = match Self::get_ordinal_content(server_config.deadpool, inscription_id.to_string()).await {
      Ok(content_blob) => content_blob,
      Err(error) => {
        log::warn!("Error getting /inscription: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving {}", inscription_id.to_string()),
        ).into_response();
      }
    };
    let bytes = content_blob.content;
    let content_type = content_blob.content_type;
    (
      ([(axum::http::header::CONTENT_TYPE, content_type),
        (axum::http::header::CACHE_CONTROL, "public, max-age=31536000".to_string())]),
      bytes,
    ).into_response()
  }

  async fn inscription_number(Path(number): Path<i64>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let content_blob = match Self::get_ordinal_content_by_number(server_config.deadpool,  number).await {
      Ok(content_blob) => content_blob,
      Err(error) => {
        log::warn!("Error getting /inscription_number: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving {}", number.to_string()),
        ).into_response();
      }
    };
    let bytes = content_blob.content;
    let content_type = content_blob.content_type;
    (
      ([(axum::http::header::CONTENT_TYPE, content_type),
        (axum::http::header::CACHE_CONTROL, "public, max-age=31536000".to_string())]),
      bytes,
    ).into_response()
  }

  async fn inscription_sha256(Path(sha256): Path<String>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let content_blob = match Self::get_ordinal_content_by_sha256(server_config.deadpool, sha256.clone(), None).await {
      Ok(content_blob) => content_blob,
      Err(error) => {
        log::warn!("Error getting /inscription_sha256: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving inscription by sha256: {}", sha256),
        ).into_response();
      }
    };
    let bytes = content_blob.content;
    let content_type = content_blob.content_type;
    (
      ([(axum::http::header::CONTENT_TYPE, content_type),
        (axum::http::header::CACHE_CONTROL, "public, max-age=31536000".to_string())]),
      bytes,
    ).into_response()
  }

  async fn inscription_metadata(Path(inscription_id): Path<InscriptionId>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let metadata = match Self::get_ordinal_metadata(server_config.deadpool, inscription_id.to_string()).await {
      Ok(metadata) => metadata,
      Err(error) => {
        log::warn!("Error getting /inscription_metadata: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving metadata for {}", inscription_id.to_string()),
        ).into_response();
      }
    
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json"),
        (axum::http::header::CACHE_CONTROL, "public, max-age=31536000")]),
      Json(metadata),
    ).into_response()
  }

  async fn inscription_metadata_number(Path(number): Path<i64>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let metadata = match Self::get_ordinal_metadata_by_number(server_config.deadpool, number).await {
      Ok(metadata) => metadata,
      Err(error) => {
        log::warn!("Error getting /inscription_metadata_number: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving metadata for {}", number.to_string()),
        ).into_response();
      }
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json"),
        (axum::http::header::CACHE_CONTROL, "public, max-age=31536000")]),
      Json(metadata),
    ).into_response()
  }

  async fn inscription_editions(Path(inscription_id): Path<InscriptionId>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let editions = match Self::get_matching_inscriptions(server_config.deadpool, inscription_id.to_string()).await {
      Ok(editions) => editions,
      Err(error) => {
        log::warn!("Error getting /inscription_editions: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving editions for {}", inscription_id.to_string()),
        ).into_response();
      }
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(editions),
    ).into_response()
  }

  async fn inscription_editions_number(Path(number): Path<i64>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let editions = match Self::get_matching_inscriptions_by_number(server_config.deadpool, number).await {
      Ok(editions) => editions,
      Err(error) => {
        log::warn!("Error getting /inscription_editions_number: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving editions for {}", number),
        ).into_response();
      }
    
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(editions),
    ).into_response()
  }

  async fn inscription_editions_sha256(Path(sha256): Path<String>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let editions = match Self::get_matching_inscriptions_by_sha256(server_config.deadpool, sha256.clone()).await {
      Ok(editions) => editions,
      Err(error) => {
        log::warn!("Error getting /inscription_editions_sha256: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving editions for {}", sha256),
        ).into_response();
      }
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(editions),
    ).into_response()
  }

  async fn inscriptions_in_block(Path(block): Path<i64>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let inscriptions = match Self::get_inscriptions_within_block(server_config.deadpool, block).await {
      Ok(inscriptions) => inscriptions,
      Err(error) => {
        log::warn!("Error getting /inscriptions_in_block: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving inscriptions for block {}", block.to_string()),
        ).into_response();
      }
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json"),
      (axum::http::header::CACHE_CONTROL, "public, max-age=31536000")]),
      Json(inscriptions),
    ).into_response()
  }

  async fn random_inscription(State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let mut rng = rand::rngs::StdRng::from_entropy();
    let random_float = rng.gen::<f64>();
    let (inscription_number, _band) = match Self::get_random_inscription(server_config.deadpool, random_float).await {
      Ok((inscription_number, band)) => (inscription_number, band),
      Err(error) => {
        log::warn!("Error getting /random_inscription: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving random inscription"),
        ).into_response();
      }
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(inscription_number),
    ).into_response()
  }

  async fn random_inscriptions(n: Query<QueryNumber>, State(server_config): State<ApiServerConfig>, session: Session<SessionNullPool>) -> impl axum::response::IntoResponse {
    let mut bands: Vec<(f64, f64)> = session.get("bands_seen").unwrap_or(Vec::new());
    for band in bands.iter() {
        println!("Band: {:?}", band);
    }
    let n = n.0.n;
    let (inscription_numbers, new_bands) = match Self::get_random_inscriptions(server_config.deadpool, n, bands).await {
      Ok((inscription_numbers, new_bands)) => (inscription_numbers, new_bands),
      Err(error) => {
        log::warn!("Error getting /random_inscriptions: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving random inscriptions"),
        ).into_response();
      }
    };
    session.set("bands_seen", new_bands);
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(inscription_numbers),
    ).into_response()
  }

  async fn recent_inscriptions(n: Query<QueryNumber>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let n = n.0.n;
    let inscriptions = match Self::get_recent_inscriptions(server_config.deadpool, n).await {
      Ok(inscriptions) => inscriptions,
      Err(error) => {
        log::warn!("Error getting /recent_inscriptions: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving recent inscriptions"),
        ).into_response();
      }
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(inscriptions),
    ).into_response()
  }

  async fn inscriptions(params: Query<InscriptionQueryParams>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    //1. parse params
    let params = ParsedInscriptionQueryParams::from(params.0);
    //2. validate params
    for content_type in &params.content_types {
      if !["text", "image", "gif", "audio", "video", "html", "json"].contains(&content_type.as_str()) {
        return (
          StatusCode::BAD_REQUEST,
          format!("Invalid content_type: {}", content_type),
        ).into_response();
      }
    }
    for satribute in &params.satributes {
      if !["vintage", "nakamoto", "firsttransaction", "palindrome", "pizza", "block9", "block9_450", "block78", "alpha", "omega", "uniform_palinception", "perfect_palinception", "block286", "jpeg", 
           "uncommon", "rare", "epic", "legendary", "mythic", "black_uncommon", "black_rare", "black_epic", "black_legendary"].contains(&satribute.as_str()) {
        return (
          StatusCode::BAD_REQUEST,
          format!("Invalid satribute: {}", satribute),
        ).into_response();
      }
    }
    if !["newest", "oldest", "newest_sat", "oldest_sat", "rarest_sat", "commonest_sat", "biggest", "smallest", "highest_fee", "lowest_fee"].contains(&params.sort_by.as_str()) {
      return (
        StatusCode::BAD_REQUEST,
        format!("Invalid sort_by: {}", params.sort_by),
      ).into_response();
    }
    let inscriptions = match Self::get_inscriptions(server_config.deadpool, params).await {
      Ok(inscriptions) => inscriptions,
      Err(error) => {
        log::warn!("Error getting /inscriptions: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving inscriptions"),
        ).into_response();
      }
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(inscriptions),
    ).into_response()
  }

  async fn inscription_last_transfer(Path(inscription_id): Path<InscriptionId>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let transfer = match Self::get_last_ordinal_transfer(server_config.deadpool, inscription_id.to_string()).await {
      Ok(transfer) => transfer,
      Err(error) => {
        log::warn!("Error getting /inscription_last_transfer: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving last transfer for {}", inscription_id.to_string()),
        ).into_response();
      }    
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(transfer),
    ).into_response()
  }

  async fn inscription_last_transfer_number(Path(number): Path<i64>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let transfer = match Self::get_last_ordinal_transfer_by_number(server_config.deadpool, number).await {
      Ok(transfer) => transfer,
      Err(error) => {
        log::warn!("Error getting /inscription_last_transfer_number: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving last transfer for {}", number),
        ).into_response();
      }
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(transfer),
    ).into_response()
  }

  async fn inscription_transfers(Path(inscription_id): Path<InscriptionId>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let transfers = match Self::get_ordinal_transfers(server_config.deadpool, inscription_id.to_string()).await {
      Ok(transfers) => transfers,
      Err(error) => {
        log::warn!("Error getting /inscription_transfers: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving transfers for {}", inscription_id.to_string()),
        ).into_response();
      }
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(transfers),
    ).into_response()
  }

  async fn inscription_transfers_number(Path(number): Path<i64>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let transfers = match Self::get_ordinal_transfers_by_number(server_config.deadpool, number).await {
      Ok(transfers) => transfers,
      Err(error) => {
        log::warn!("Error getting /inscription_transfers_number: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving transfers for {}", number),
        ).into_response();
      }
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(transfers),
    ).into_response()
  }

  async fn inscriptions_in_address(Path(address): Path<String>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let inscriptions: Vec<TransferWithMetadata> = match Self::get_inscriptions_by_address(server_config.deadpool, address.clone()).await {
      Ok(inscriptions) => inscriptions,
      Err(error) => {
        log::warn!("Error getting /inscriptions_in_address: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving inscriptions for {}", address),
        ).into_response();
      }
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(inscriptions),
    ).into_response()
  }

  async fn inscriptions_on_sat(Path(sat): Path<i64>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let inscriptions: Vec<Metadata> = match Self::get_inscriptions_on_sat(server_config.deadpool, sat).await {
      Ok(inscriptions) => inscriptions,
      Err(error) => {
        log::warn!("Error getting /inscriptions_on_sat: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving inscriptions for {}", sat),
        ).into_response();
      }
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(inscriptions),
    ).into_response()
  }

  async fn inscriptions_in_sat_block(Path(block): Path<i64>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let inscriptions: Vec<Metadata> = match Self::get_inscriptions_in_sat_block(server_config.deadpool, block).await {
      Ok(inscriptions) => inscriptions,
      Err(error) => {
        log::warn!("Error getting /inscriptions_in_sat_block: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving inscriptions for {}", block),
        ).into_response();
      }
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(inscriptions),
    ).into_response()
  }

  async fn sat_metadata(Path(sat): Path<i64>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let sat_metadata = match Self::get_sat_metadata(server_config.deadpool, sat).await {
      Ok(sat_metadata) => sat_metadata,
      Err(error) => {
        log::warn!("Error getting /sat_metadata: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving metadata for {}", sat),
        ).into_response();
      }    
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(sat_metadata),
    ).into_response()
  }

  async fn satributes(Path(sat): Path<i64>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let satributes = match Self::get_satributes(server_config.deadpool, sat).await {
      Ok(satributes) => satributes,
      Err(error) => {
        log::warn!("Error getting /satributes: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving satributes for {}", sat),
        ).into_response();
      }
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(satributes),
    ).into_response()
  }

  async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("expect tokio signal ctrl-c");
  }

  //DB functions
  async fn insert_satribute_criteria(pool: mysql_async::Pool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut satribute_criteria = Vec::new();
    let mut rdr = csv::Reader::from_path("satributes.csv")?;
    for result in rdr.deserialize() {
      let record: SatributeCriteria = result?;
      satribute_criteria.push(record);
    }
    for chunk in satribute_criteria.chunks(5000) {
      let insert_result = Self::bulk_insert(pool.clone(), 
        "satribute_criteria_new".to_string(), 
        vec![
          "satribute".to_string(), 
          "sat".to_string(), 
          "sat_range_start".to_string(),
          "sat_range_end".to_string(),
          "block".to_string(),
          "block_range_start".to_string(),
          "block_range_end".to_string()
        ],
        chunk.to_vec(), 
        |object| {
        params! {
            "satribute" => &object.satribute,
            "sat" => object.sat,
            "sat_range_start" => object.sat_range_start,
            "sat_range_end" => &object.sat_range_end,
            "block" => object.block,
            "block_range_start" => object.block_range_start,
            "block_range_end" => &object.block_range_end,
        }
      }).await;
      match insert_result {
        Ok(_) => {
          let mut conn = Self::get_conn(pool.clone()).await?;
          conn.query_drop("RENAME TABLE satribute_criteria to satribute_criteria_old, satribute_criteria_new to satribute_criteria").await?;
          conn.query_drop("DROP TABLE if exists satribute_criteria_old").await?;
        },
        Err(error) => {
          log::warn!("Error bulk inserting satribute criteria: {}", error);
          return Err(Box::new(error));
        }
      };
    }
    Ok(())
  }

  async fn get_ordinal_content_s3(client: &s3::Client, bucket_name: &str, inscription_id: String) -> GetObjectOutput {
    let key = format!("content/{}", inscription_id);
    let content = client
      .get_object()
      .bucket(bucket_name)
      .key(key)
      .send()
      .await
      .unwrap();
    content
  }

  async fn get_ordinal_content(pool: deadpool, inscription_id: String) -> anyhow::Result<ContentBlob> {
    let conn = pool.clone().get().await?;
    let row = conn.query_one(
      "SELECT sha256, content_type FROM ordinals WHERE id=$1 LIMIT 1",
      &[&inscription_id]
    ).await?;
    let sha256: String = row.get(0);
    let content_type: String = row.get(1);
    let content = Self::get_ordinal_content_by_sha256(pool, sha256, Some(content_type)).await;
    content
  }

  async fn get_ordinal_content_by_number(pool: deadpool, number: i64) -> anyhow::Result<ContentBlob> {
    let conn = pool.clone().get().await?;
    let row = conn.query_one(
      "SELECT sha256, content_type FROM ordinals WHERE number=$1 LIMIT 1",
      &[&number]
    ).await?;
    let sha256: String = row.get(0);
    let content_type: String = row.get(1);
    let content = Self::get_ordinal_content_by_sha256(pool, sha256, Some(content_type)).await;
    content
  }

  async fn get_ordinal_content_by_sha256(pool: deadpool, sha256: String, content_type_override: Option<String>) -> anyhow::Result<ContentBlob> {
    let conn = pool.get().await?;
    let moderation_flag = conn.query_one(
      r"SELECT coalesce(human_override_moderation_flag, automated_moderation_flag)
              FROM content_moderation
              WHERE sha256=$1
              LIMIT 1",
      &[&sha256]
    ).await?;
    let moderation_flag: Option<String> = moderation_flag.get(0);

    if let Some(flag) = moderation_flag {
        if flag == "SAFE_MANUAL" || flag == "SAFE_AUTOMATED" {
            //Proceed as normal
        } else {
          let content = ContentBlob {
              sha256: sha256.clone(),
              content: std::fs::read("blocked.png")?,
              content_type: "image/png".to_string(),
          };
          return Ok(content);
        }
    } else {
      let content = ContentBlob {
        sha256: sha256.clone(),
        content: "This content hasn't been indexed yet.".as_bytes().to_vec(),
        content_type: "text/plain".to_string(),
      };
      return Ok(content);
    }
    //Proceed if safe
    let row = conn.query_one(
      r"SELECT *
              FROM content
              WHERE sha256=$1
              LIMIT 1",
      &[&sha256]
    ).await?;
    let mut content_blob = ContentBlob {
      sha256: row.get("sha256"),
      content: row.get("content"),
      content_type: row.get("content_type"),
    };
    if let Some(content_type) = content_type_override {
      content_blob.content_type = content_type;
    }
    Ok(content_blob)
  }

  fn map_row_to_metadata(mut row: mysql_async::Row) -> Metadata {
    Metadata {
      id: row.get("id").unwrap(),
      content_length: row.take("content_length").unwrap(),
      content_type: row.take("content_type").unwrap(), 
      content_encoding: row.take("content_encoding").unwrap(),
      genesis_fee: row.get("genesis_fee").unwrap(),
      genesis_height: row.get("genesis_height").unwrap(),
      genesis_transaction: row.get("genesis_transaction").unwrap(),
      pointer: row.take("pointer").unwrap(),
      number: row.get("number").unwrap(),
      sequence_number: row.take("sequence_number").unwrap(),
      parent: row.take("parent").unwrap(),
      delegate: row.take("delegate").unwrap(),
      metaprotocol: row.take("metaprotocol").unwrap(),
      embedded_metadata: row.take("embedded_metadata").unwrap(),
      sat: row.take("sat").unwrap(),
      satributes: Vec::new(),
      charms: row.take("charms").unwrap(),
      timestamp: row.get("timestamp").unwrap(),
      sha256: row.take("sha256").unwrap(),
      text: row.take("text").unwrap(),
      is_json: row.get("is_json").unwrap(),
      is_maybe_json: row.get("is_maybe_json").unwrap(),
      is_bitmap_style: row.get("is_bitmap_style").unwrap(),
      is_recursive: row.get("is_recursive").unwrap()
    }
  }

  fn map_row_to_metadata2(row: tokio_postgres::Row) -> Metadata {
    Metadata {
      id: row.get("id"),
      content_length: row.get("content_length"),
      content_type: row.get("content_type"), 
      content_encoding: row.get("content_encoding"),
      genesis_fee: row.get("genesis_fee"),
      genesis_height: row.get("genesis_height"),
      genesis_transaction: row.get("genesis_transaction"),
      pointer: row.get("pointer"),
      number: row.get("number"),
      sequence_number: row.get("sequence_number"),
      parent: row.get("parent"),
      delegate: row.get("delegate"),
      metaprotocol: row.get("metaprotocol"),
      embedded_metadata: row.get("embedded_metadata"),
      sat: row.get("sat"),
      satributes: row.get("satributes"),
      charms: row.get("charms"),
      timestamp: row.get("timestamp"),
      sha256: row.get("sha256"),
      text: row.get("text"),
      is_json: row.get("is_json"),
      is_maybe_json: row.get("is_maybe_json"),
      is_bitmap_style: row.get("is_bitmap_style"),
      is_recursive: row.get("is_recursive")
    }
  }

  async fn get_ordinal_metadata(pool: deadpool, inscription_id: String) -> anyhow::Result<Metadata> {
    let conn = pool.get().await?;
    let result = conn.query_one(
      "SELECT * FROM ordinals WHERE id=$1 LIMIT 1", 
      &[&inscription_id]
    ).await?;
    Ok(Self::map_row_to_metadata2(result))
  }

  async fn get_ordinal_metadata_by_number(pool: deadpool, number: i64) -> anyhow::Result<Metadata> {
    let conn = pool.get().await?;
    let result = conn.query_one(
      "SELECT * FROM ordinals WHERE number=$1 LIMIT 1", 
      &[&number]
    ).await?;
    Ok(Self::map_row_to_metadata2(result))
  }

  async fn get_matching_inscriptions(pool: deadpool, inscription_id: String) -> anyhow::Result<Vec<InscriptionNumberEdition>> {
    let conn = pool.get().await?;
    let result = conn.query(
      "with a as (select sha256 from editions where id = $1) select id, number, edition, t.total from a left join editions e on a.sha256=e.sha256 left join editions_total t on t.sha256=a.sha256 order by edition asc limit 100",
      &[&inscription_id]
    ).await?;
    let mut editions = Vec::new();
    for row in result {
      editions.push(InscriptionNumberEdition {
        id: row.get("id"),
        number: row.get("number"),
        edition: row.get("edition"),
        total: row.get("total")
      });
    }
    Ok(editions)
  }

  async fn get_matching_inscriptions_by_number(pool: deadpool, number: i64) -> anyhow::Result<Vec<InscriptionNumberEdition>> {
    let conn = pool.get().await?;
    let result = conn.query(
      "with a as (select sha256 from editions where number = $1) select id, number, edition, t.total from a left join editions e on a.sha256=e.sha256 left join editions_total t on t.sha256=a.sha256 order by edition asc limit 100",
      &[&number]
    ).await?;
    let mut editions = Vec::new();
    for row in result {
      editions.push(InscriptionNumberEdition {
        id: row.get("id"),
        number: row.get("number"),
        edition: row.get("edition"),
        total: row.get("total")
      });
    }
    Ok(editions)
  }

  async fn get_matching_inscriptions_by_sha256(pool: deadpool, sha256: String) -> anyhow::Result<Vec<InscriptionNumberEdition>> {
    let conn = pool.get().await?;
    let result = conn.query(
      "select id, number, edition, t.total from (select * from editions where sha256=:sha256) e inner join editions_total t on t.sha256=e.sha256 order by edition asc limit 100",
      &[&sha256]
    ).await?;
    let mut editions = Vec::new();
    for row in result {
      editions.push(InscriptionNumberEdition {
        id: row.get("id"),
        number: row.get("number"),
        edition: row.get("edition"),
        total: row.get("total")
      });
    }
    Ok(editions)
  }

  async fn get_inscriptions_within_block(pool: deadpool, block: i64) -> anyhow::Result<Vec<Metadata>> {
    let conn = pool.get().await?;
    let result = conn.query(
      "SELECT * FROM ordinals WHERE genesis_height=$1", 
      &[&block]
    ).await?;
    let mut inscriptions = Vec::new();
    for row in result {
      inscriptions.push(Self::map_row_to_metadata2(row));
    }
    Ok(inscriptions)
  }
  
  async fn get_random_inscription(pool: deadpool, random_float: f64) -> anyhow::Result<(Metadata, (f64, f64))> {
    let conn = pool.get().await?;
    let random_inscription_band = conn.query_one(
      "SELECT first_number, class_band_start, class_band_end FROM weights where band_end>$1 limit 1",
      &[&random_float]
    ).await?;
    let random_inscription_band = RandomInscriptionBand {
      sequence_number: random_inscription_band.get("first_number"),
      start: random_inscription_band.get("class_band_start"),
      end: random_inscription_band.get("class_band_end")
    };
    let metadata = conn.query_one(
      "SELECT * from ordinals where sequence_number=$1 limit 1", 
      &[&random_inscription_band.sequence_number]
    ).await?;
    let metadata = Self::map_row_to_metadata2(metadata);
    Ok((metadata,(random_inscription_band.start, random_inscription_band.end)))
  }

  async fn get_random_inscriptions(pool: deadpool, n: u32, mut bands: Vec<(f64, f64)>) -> anyhow::Result<(Vec<Metadata>, Vec<(f64, f64)>)> {
    let n = std::cmp::min(n, 100);
    let mut rng = rand::rngs::StdRng::from_entropy();
    let mut random_floats = Vec::new();
    while random_floats.len() < n as usize {
      let random_float = rng.gen::<f64>();
      let mut already_seen = false;
      for band in bands.iter() {
        if random_float >= band.0 && random_float < band.1 {
          already_seen = true;
          break;
        }
      }
      if !already_seen {
        random_floats.push(random_float);
      }
    }

    let mut set = JoinSet::new();
    let mut random_metadatas = Vec::new();
    for i in 0..n {
      set.spawn(Self::get_random_inscription(pool.clone(), random_floats[i as usize]));
    }
    while let Some(res) = set.join_next().await {
      let random_inscription_details = res??;
      random_metadatas.push(random_inscription_details.0);
      bands.push(random_inscription_details.1);
    }
    Ok((random_metadatas, bands))
  }

  async fn get_recent_inscriptions(pool: deadpool, n: u32) -> anyhow::Result<Vec<Metadata>> {
    let conn = pool.get().await?;
    let result = conn.query(
      "SELECT * FROM ordinals order by sequence_number desc limit $1", 
      &[&n]
    ).await?;
    let mut inscriptions = Vec::new();
    for row in result {
      inscriptions.push(Self::map_row_to_metadata2(row));
    }
    Ok(inscriptions)
  }

  async fn get_inscriptions(pool: deadpool, params: ParsedInscriptionQueryParams) -> anyhow::Result<Vec<Metadata>> {
    let conn = pool.get().await?;
    //1. build query
    let mut query = "SELECT o.* FROM ordinals o WHERE 1=1".to_string();
    if params.content_types.len() > 0 {
      query.push_str(" AND (");
      for (i, content_type) in params.content_types.iter().enumerate() {
        if content_type == "text" {
          query.push_str("(o.content_type IN ('text/plain;charset=utf-8', 'text/plain','text/markdown', 'text/javascript', 'text/plain;charset=us-ascii', 'text/rtf') AND o.is_json=false AND o.is_maybe_json=false AND o.is_bitmap_style=false)");
        } else if content_type == "image" {
          query.push_str("o.content_type IN ('image/jpeg', 'image/png', 'image/svg+xml', 'image/webp', 'image/avif', 'image/tiff', 'image/heic', 'image/jp2')");
        } else if content_type == "gif" {
          query.push_str("o.content_type = 'image/gif'");
        } else if content_type == "audio" {
          query.push_str("o.content_type IN ('audio/mpeg', 'audio/ogg', 'audio/wav', 'audio/webm', 'audio/flac', 'audio/mod', 'audio/midi', 'audio/x-m4a')");
        } else if content_type == "video" {
          query.push_str("o.content_type IN ('video/mp4', 'video/ogg', 'video/webm'");
        } else if content_type == "html" {
          query.push_str("o.content_type IN ('text/html;charset=utf-8', 'text/html')");
        } else if content_type == "json" {
          query.push_str("o.is_json=true");
        } else if content_type == "namespace" {
          query.push_str("o.is_bitmap_style=true");
        }
        if i < params.content_types.len() - 1 {
          query.push_str(" OR ");
        }
      }
      query.push_str(")");
    }
    if params.satributes.len() > 0 {
      query.push_str(format!(" AND (o.satributes && array['{}'::varchar])", params.satributes.join("'::varchar,'")).as_str());
    }
    if params.sort_by == "newest" {
      query.push_str(" ORDER BY o.sequence_number DESC");
    } else if params.sort_by == "oldest" {
      query.push_str(" ORDER BY o.sequence_number ASC");
    } else if params.sort_by == "newest_sat" {
      query.push_str(" ORDER BY o.sat DESC");
    } else if params.sort_by == "oldest_sat" {
      query.push_str(" ORDER BY o.sat ASC");
    } else if params.sort_by == "rarest_sat" {
      //query.push_str(" ORDER BY o.sat ASC");
    } else if params.sort_by == "commonest_sat" {
      //query.push_str(" ORDER BY o.sat DESC");
    } else if params.sort_by == "biggest" {
      query.push_str(" ORDER BY o.content_length DESC");
    } else if params.sort_by == "smallest" {
      query.push_str(" ORDER BY o.content_length ASC");
    } else if params.sort_by == "highest_fee" {
      query.push_str(" ORDER BY o.genesis_fee DESC");
    } else if params.sort_by == "lowest_fee" {
      query.push_str(" ORDER BY o.genesis_fee ASC");
    }
    if params.page_size > 0 {
      query.push_str(format!(" LIMIT {}", params.page_size).as_str());
    }
    if params.page_number > 0 {
      query.push_str(format!(" OFFSET {}", params.page_number * params.page_size).as_str());
    }
    println!("Query: {}", query);
    let result = conn.query(
      query.as_str(), 
      &[]
    ).await?;
    let mut inscriptions = Vec::new();
    for row in result {
      inscriptions.push(Self::map_row_to_metadata2(row));
    }
    Ok(inscriptions)
  }

  async fn get_conn(pool: mysql_async::Pool) -> Result<mysql_async::Conn, mysql_async::Error> {
    let conn = pool.get_conn().await;
    conn
  }

  async fn get_deadpool(config: Config) -> anyhow::Result<deadpool> {
    let mut deadpool_cfg = deadpool_postgres::Config::new();
    deadpool_cfg.host = config.db_host;
    deadpool_cfg.dbname = config.db_name;
    deadpool_cfg.user = config.db_user;
    deadpool_cfg.password = config.db_password;
    deadpool_cfg.manager = Some(ManagerConfig { recycling_method: RecyclingMethod::Fast });
    let deadpool = deadpool_cfg.create_pool(Some(deadpool_postgres::Runtime::Tokio1), NoTls)?;
    Ok(deadpool)
  }

  async fn get_last_ordinal_transfer(pool: deadpool, inscription_id: String) -> anyhow::Result<Transfer> {
    let conn = pool.get().await?;
    let result = conn.query_one(
      "SELECT * FROM transfers WHERE id=$1 ORDER BY block_number DESC LIMIT 1", 
      &[&inscription_id]
    ).await?;
    let transfer = Transfer {
      id: result.get("id"),
      block_number: result.get("block_number"),
      block_timestamp: result.get("block_timestamp"),
      satpoint: result.get("satpoint"),
      transaction: result.get("transaction"),
      vout: result.get("vout"),
      offset: result.get("offset"),
      address: result.get("address"),
      is_genesis: result.get("is_genesis")
    };
    Ok(transfer)
  }

  async fn get_last_ordinal_transfer_by_number(pool: deadpool, number: i64) -> anyhow::Result<Transfer> {
    let conn = pool.get().await?;
    let result = conn.query_one(
      "with a as (Select id from ordinals where number=$1) select b.* from transfers b, a where a.id=b.id order by block_number desc limit 1", 
      &[&number]
    ).await?;
    let transfer = Transfer {
      id: result.get("id"),
      block_number: result.get("block_number"),
      block_timestamp: result.get("block_timestamp"),
      satpoint: result.get("satpoint"),
      transaction: result.get("transaction"),
      vout: result.get("vout"),
      offset: result.get("offset"),
      address: result.get("address"),
      is_genesis: result.get("is_genesis")
    };
    Ok(transfer)
  }

  async fn get_ordinal_transfers(pool: deadpool, inscription_id: String) -> anyhow::Result<Vec<Transfer>> {
    let conn = pool.get().await?;
    let result = conn.query(
      "SELECT * FROM transfers WHERE id=$1 ORDER BY block_number ASC", 
      &[&inscription_id]
    ).await?;
    let mut transfers = Vec::new();
    for row in result {
      transfers.push(Transfer {
        id: row.get("id"),
        block_number: row.get("block_number"),
        block_timestamp: row.get("block_timestamp"),
        satpoint: row.get("satpoint"),
        transaction: row.get("transaction"),
        vout: row.get("vout"),
        offset: row.get("offset"),
        address: row.get("address"),
        is_genesis: row.get("is_genesis")
      });
    }
    Ok(transfers)
  }

  async fn get_ordinal_transfers_by_number(pool: deadpool, number: i64) -> anyhow::Result<Vec<Transfer>> {
    let conn = pool.get().await?;
    let result = conn.query(
      "with a as (Select id from ordinals where number=$1) select b.* from transfers b, a where a.id=b.id order by block_number desc", 
      &[&number]
    ).await?;
    let mut transfers = Vec::new();
    for row in result {
      transfers.push(Transfer {
        id: row.get("id"),
        block_number: row.get("block_number"),
        block_timestamp: row.get("block_timestamp"),
        satpoint: row.get("satpoint"),
        transaction: row.get("transaction"),
        vout: row.get("vout"),
        offset: row.get("offset"),
        address: row.get("address"),
        is_genesis: row.get("is_genesis")
      });
    }
    Ok(transfers)
  }

  async fn get_inscriptions_by_address(pool: deadpool, address: String) -> anyhow::Result<Vec<TransferWithMetadata>> {
    let conn = pool.get().await?;
    let result = conn.query(
      "SELECT a.*, o.* FROM addresses a LEFT JOIN ordinals o ON a.id=o.id WHERE a.address=$1", 
      &[&address]
    ).await?;
    let mut transfers = Vec::new();
    for row in result {
      transfers.push(TransferWithMetadata {
        id: row.get("id"),
        block_number: row.get("block_number"),
        block_timestamp: row.get("block_timestamp"),
        satpoint: row.get("satpoint"),
        transaction: row.get("transaction"),
        vout: row.get("vout"),
        offset: row.get("offset"),
        address: row.get("address"),
        is_genesis: row.get("is_genesis"),
        content_length: row.get("content_length"),
        content_type: row.get("content_type"),
        content_encoding: row.get("content_encoding"),
        genesis_fee: row.get("genesis_fee"),
        genesis_height: row.get("genesis_height"),
        genesis_transaction: row.get("genesis_transaction"),
        pointer: row.get("pointer"),
        number: row.get("number"),
        sequence_number: row.get("sequence_number"),
        parent: row.get("parent"),
        delegate: row.get("delegate"),
        metaprotocol: row.get("metaprotocol"),
        embedded_metadata: row.get("embedded_metadata"),
        sat: row.get("sat"),
        charms: row.get("charms"),
        timestamp: row.get("timestamp"),
        sha256: row.get("sha256"),
        text: row.get("text"),
        is_json: row.get("is_json"),
        is_maybe_json: row.get("is_maybe_json"),
        is_bitmap_style: row.get("is_bitmap_style"),
        is_recursive: row.get("is_recursive")
      });
    }
    Ok(transfers)
  }

  async fn get_inscriptions_on_sat(pool: deadpool, sat: i64) -> anyhow::Result<Vec<Metadata>> {
    let conn = pool.get().await?;
    let result = conn.query(
      "SELECT * FROM ordinals WHERE sat=$1", 
      &[&sat]
    ).await?;
    let mut inscriptions = Vec::new();
    for row in result {
      inscriptions.push(Self::map_row_to_metadata2(row));
    }
    Ok(inscriptions)
  }

  async fn get_inscriptions_in_sat_block(pool: deadpool, block: i64) -> anyhow::Result<Vec<Metadata>> {
    let conn = pool.get().await?;
    let result = conn.query(
      "select * from ordinals where sat in (select sat from sat where block=$1)", 
      &[&block]
    ).await?;
    let mut inscriptions = Vec::new();
    for row in result {
      inscriptions.push(Self::map_row_to_metadata2(row));
    }
    Ok(inscriptions)
  }

  async fn get_sat_metadata(pool: deadpool, sat: i64) -> anyhow::Result<SatMetadata> {
    let conn = pool.get().await?;
    let result = conn.query_one(
      "SELECT * FROM sat WHERE sat=$1 limit 1", 
      &[&sat]
    ).await;
    let sat_metadata = match result {
      Ok(result) => {
        SatMetadata {
          sat: result.get("sat"),
          satributes: result.get("satributes"),
          decimal: result.get("sat_decimal"),
          degree: result.get("degree"),
          name: result.get("name"),
          block: result.get("block"),
          cycle: result.get("cycle"),
          epoch: result.get("epoch"),
          period: result.get("period"),
          third: result.get("offset"),
          rarity: result.get("rarity"),
          percentile: result.get("percentile"),
          timestamp: result.get("timestamp")
        }      
      },
      Err(_) => {
        let parsed_sat = Sat(sat as u64);
        let mut satributes = parsed_sat.block_rarities().iter().map(|x| x.to_string()).collect::<Vec<String>>();
        if !parsed_sat.common() {
          satributes.push(parsed_sat.rarity().to_string()); 
        }
        let mut metadata = SatMetadata {
          sat: sat.try_into().unwrap(),
          satributes: satributes,
          decimal: parsed_sat.decimal().to_string(),
          degree: parsed_sat.degree().to_string(),
          name: parsed_sat.name(),
          block: parsed_sat.height().0 as i64,
          cycle: parsed_sat.cycle() as i64,
          epoch: parsed_sat.epoch().0 as i64,
          period: parsed_sat.period() as i64,
          third: parsed_sat.third() as i64,
          rarity: parsed_sat.rarity().to_string(),
          percentile: parsed_sat.percentile(),
          timestamp: 0
        };
        let blockheight_result = conn.query_one(
          "Select * from blockheights where block_number=$1 limit 1", 
          &[&metadata.block]
        ).await?;
        let blockheight = BlockHeight {
          block_number: blockheight_result.get("block_number"),
          block_timestamp: blockheight_result.get("block_timestamp")
        };
        metadata.timestamp = blockheight.block_timestamp;
        metadata
      }
    };
    Ok(sat_metadata)
  }

  async fn get_satributes(pool: deadpool, sat: i64) -> anyhow::Result<Vec<Satribute>> {
    let conn = pool.get().await?;
    let result = conn.query(
      "SELECT * FROM satributes WHERE sat=$1", 
      &[&sat]
    ).await?;
    let mut satributes = Vec::new();
    for row in result {
      satributes.push(Satribute {
        sat: row.get("sat"),
        satribute: row.get("satribute"),
      });
    }
    if satributes.len() == 0 {
      let parsed_sat = Sat(sat as u64);
      for block_rarity in parsed_sat.block_rarities().iter() {
        let satribute = Satribute {
          sat: sat as i64,
          satribute: block_rarity.to_string()
        };
        satributes.push(satribute);
      }
    }
    Ok(satributes)
  }

  async fn create_metadata_insert_trigger(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(r"CREATE OR REPLACE FUNCTION before_metadata_insert() RETURNS TRIGGER AS $$
      BEGIN
        -- RAISE NOTICE 'insert_metadata: waiting for lock';
        LOCK TABLE ordinals IN EXCLUSIVE MODE;
        -- RAISE NOTICE 'insert_metadata: lock acquired';
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql;").await?;
    conn.simple_query(
      r#"CREATE OR REPLACE TRIGGER before_metadata_insert
      BEFORE INSERT ON ordinals
      FOR EACH ROW
      EXECUTE PROCEDURE before_metadata_insert();"#).await?;
    Ok(())
  }

  async fn create_edition_insert_trigger(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(r#"
      CREATE OR REPLACE FUNCTION before_edition_insert() RETURNS TRIGGER AS $$
      DECLARE previous_total INTEGER;
      DECLARE new_total INTEGER;
      BEGIN
        -- Get the previous total for the same sha256, or default to 0
        SELECT total INTO previous_total FROM editions_total WHERE sha256 = NEW.sha256;
        new_total := COALESCE(previous_total, 0) + 1;
        -- RAISE NOTICE 'previous_total: %, new_total: %', previous_total, new_total;
        -- Set the edition number in the new row to previous + 1
        NEW.edition := new_total;
      
        -- Insert or update the total in editions_total
        INSERT INTO editions_total (sha256, total) VALUES (NEW.sha256, new_total)
        ON CONFLICT (sha256) DO UPDATE SET total = EXCLUDED.total;
      
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql;"#).await?;
    conn.simple_query(
      r#"CREATE OR REPLACE TRIGGER before_edition_insert
      BEFORE INSERT ON editions
      FOR EACH ROW
      EXECUTE PROCEDURE before_edition_insert();"#).await?;
    Ok(())
  }
  
  async fn create_edition_procedure(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(r"DROP PROCEDURE IF EXISTS update_editions").await?;
    conn.simple_query(
      r#"CREATE PROCEDURE update_editions()
      LANGUAGE plpgsql
      AS $$
      BEGIN
      LOCK TABLE ordinals IN EXCLUSIVE MODE;
      RAISE NOTICE 'update_editions: lock acquired';
      IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'editions') THEN
      INSERT into proc_log(proc_name, step_name, ts) values ('EDITIONS', 'START_CREATE', now());
      CREATE TABLE editions as select id, number, sequence_number, sha256, row_number() OVER(PARTITION BY sha256 ORDER BY sequence_number asc) as edition from ordinals;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('EDITIONS', 'FINISH_CREATE', now(), NULL);
      INSERT into proc_log(proc_name, step_name, ts) values ('EDITIONS', 'START_CREATE_TOTAL', now());
      CREATE TABLE editions_total as select sha256, count(*) as total from ordinals where sha256 is not null group by sha256;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('EDITIONS', 'FINISH_CREATE_TOTAL', now(), NULL);
      ALTER TABLE editions add primary key (id);
      CREATE INDEX IF NOT EXISTS idx_number ON editions (number);
      CREATE INDEX IF NOT EXISTS idx_sha256 ON editions (sha256);
      ALTER TABLE editions_total add primary key (sha256);
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('EDITIONS', 'FINISH_INDEX', now(), NULL);
      ELSE
      DROP TABLE IF EXISTS editions_new, editions_total_new;
      INSERT into proc_log(proc_name, step_name, ts) values ('EDITIONS', 'START_CREATE_NEW', now());
      CREATE TABLE editions_new as select id, number, sequence_number, sha256, row_number() OVER(PARTITION BY sha256 ORDER BY sequence_number asc) as edition from ordinals;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('EDITIONS', 'FINISH_CREATE_NEW', now(), NULL);
      INSERT into proc_log(proc_name, step_name, ts) values ('EDITIONS', 'START_CREATE_TOTAL_NEW', now());
      CREATE TABLE editions_total_new as select sha256, count(*) as total from ordinals where sha256 is not null group by sha256;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('EDITIONS', 'FINISH_CREATE_TOTAL_NEW', now(), NULL);
      ALTER TABLE editions_new add primary key (id);
      CREATE INDEX IF NOT EXISTS idx_number ON editions_new (number);
      CREATE INDEX IF NOT EXISTS idx_sha256 ON editions_new (sha256);
      ALTER TABLE editions_total_new add primary key (sha256);
      ALTER TABLE editions RENAME to editions_old; 
      ALTER TABLE editions_new RENAME to editions;
      ALTER TABLE editions_total RENAME to editions_total_old;
      ALTER TABLE editions_total_new RENAME to editions_total;
      DROP TABLE IF EXISTS editions_old;
      DROP TABLE IF EXISTS editions_total_old;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('EDITIONS', 'FINISH_INDEX_NEW', now(), NULL);
      END IF;
      END;
      $$;"#).await?;
    Ok(())
  }
  
  async fn create_weights_procedure(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(r"DROP PROCEDURE IF EXISTS update_weights").await?;
    conn.simple_query(
      r#"CREATE OR REPLACE PROCEDURE update_weights()
      LANGUAGE plpgsql
      AS $$
      BEGIN
      DROP TABLE IF EXISTS weights_1;
      DROP TABLE IF EXISTS weights_2;
      DROP TABLE IF EXISTS weights_3;
      DROP TABLE IF EXISTS weights_4;
      DROP TABLE IF EXISTS weights_5;
      IF 'weights' NOT IN (SELECT table_name FROM information_schema.tables) THEN
      INSERT into proc_log(proc_name, step_name, ts) values ('WEIGHTS', 'START_CREATE_1', now());
        CREATE TABLE weights_1 as
        select sha256, 
               min(sequence_number) as first_number, 
               sum(genesis_fee) as total_fee, 
               max(content_length) as content_length, 
               count(*) as count
        from ordinals 
        where is_json=0 and is_bitmap_style=0 and is_maybe_json=0 and sha256 in (
          select sha256 
          from content_moderation 
          where coalesce(human_override_moderation_flag, automated_moderation_flag) = 'SAFE_MANUAL' 
          or coalesce(human_override_moderation_flag, automated_moderation_flag) = 'SAFE_AUTOMATED')
        group by sha256;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('WEIGHTS', 'FINISH_CREATE_1', now(), found_rows());
      INSERT into proc_log(proc_name, step_name, ts) values ('WEIGHTS', 'START_CREATE_2', now());
        CREATE TABLE weights_2 AS
        SELECT w.*,
              CASE
                  WHEN db.dbscan_class IS NULL THEN -w.first_number
                  WHEN db.dbscan_class = -1 THEN -w.first_number
                  ELSE db.dbscan_class
              END AS CLASS
        FROM weights_1 w
        LEFT JOIN dbscan db ON w.sha256=db.sha256;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('WEIGHTS', 'FINISH_CREATE_2', now(), found_rows());
      INSERT into proc_log(proc_name, step_name, ts) values ('WEIGHTS', 'START_CREATE_3', now());
        CREATE TABLE weights_3 AS
        SELECT sha256, 
              min(class) as class,
              min(first_number) AS first_number,
              sum(total_fee) AS total_fee
        FROM weights_2
        GROUP BY sha256;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('WEIGHTS', 'FINISH_CREATE_3', now(), found_rows());
      INSERT into proc_log(proc_name, step_name, ts) values ('WEIGHTS', 'START_CREATE_4', now());
        CREATE TABLE weights_4 AS
        SELECT *,
              (10-log(10,first_number+1))*total_fee AS weight
        FROM weights_3;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('WEIGHTS', 'FINISH_CREATE_4', now(), found_rows());
      INSERT into proc_log(proc_name, step_name, ts) values ('WEIGHTS', 'START_CREATE_5', now());
        CREATE TABLE weights_5 AS
        SELECT *,
              sum(weight) OVER(ORDER BY class, first_number)/sum(weight) OVER() AS band_end, 
              coalesce(sum(weight) OVER(ORDER BY class, first_number ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING),0)/sum(weight) OVER() AS band_start
        FROM weights_4;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('WEIGHTS', 'FINISH_CREATE_5', now(), found_rows());
      INSERT into proc_log(proc_name, step_name, ts) values ('WEIGHTS', 'START_CREATE_6', now());
      CREATE TABLE weights AS
      SELECT *,
            min(band_start) OVER(PARTITION BY class) AS class_band_start,
            max(band_end) OVER(PARTITION BY class) AS class_band_end
      FROM weights_5;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('WEIGHTS', 'FINISH_CREATE_6', now(), found_rows());
        CREATE INDEX idx_band_start ON weights (band_start);
        CREATE INDEX idx_band_end ON weights (band_end);
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('WEIGHTS', 'FINISH_INDEX', now(), found_rows());
      
      ELSE
      
      INSERT into proc_log(proc_name, step_name, ts) values ('WEIGHTS', 'START_CREATE_NEW', now());
      DROP TABLE IF EXISTS weights_new;
        CREATE TABLE weights_1 as
        select sha256, 
               min(sequence_number) as first_number, 
               sum(genesis_fee) as total_fee, 
               max(content_length) as content_length, 
               count(*) as count
        from ordinals 
        where is_json=0 and is_bitmap_style=0 and is_maybe_json=0 and sha256 in (
          select sha256 
          from content_moderation 
          where coalesce(human_override_moderation_flag, automated_moderation_flag) = 'SAFE_MANUAL' 
          or coalesce(human_override_moderation_flag, automated_moderation_flag) = 'SAFE_AUTOMATED')
        group by sha256;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('WEIGHTS', 'FINISH_CREATE_NEW_1', now(), found_rows());
      INSERT into proc_log(proc_name, step_name, ts) values ('WEIGHTS', 'START_CREATE_NEW_2', now());
        CREATE TABLE weights_2 AS
        SELECT w.*,
              CASE
                  WHEN db.dbscan_class IS NULL THEN -w.first_number
                  WHEN db.dbscan_class = -1 THEN -w.first_number
                  ELSE db.dbscan_class
              END AS CLASS
        FROM weights_1 w
        LEFT JOIN dbscan db ON w.sha256=db.sha256;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('WEIGHTS', 'FINISH_CREATE_NEW_2', now(), found_rows());
      INSERT into proc_log(proc_name, step_name, ts) values ('WEIGHTS', 'START_CREATE_NEW_3', now());
        CREATE TABLE weights_3 AS
        SELECT sha256, 
              min(class) as class,
              min(first_number) AS first_number,
              sum(total_fee) AS total_fee
        FROM weights_2
        GROUP BY sha256;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('WEIGHTS', 'FINISH_CREATE_NEW_3', now(), found_rows());
      INSERT into proc_log(proc_name, step_name, ts) values ('WEIGHTS', 'START_CREATE_NEW_4', now());
        CREATE TABLE weights_4 AS
        SELECT *,
              (10-log(10,first_number+1))*total_fee AS weight
        FROM weights_3;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('WEIGHTS', 'FINISH_CREATE_NEW_4', now(), found_rows());
      INSERT into proc_log(proc_name, step_name, ts) values ('WEIGHTS', 'START_CREATE_NEW_5', now());
        CREATE TABLE weights_5 AS
        SELECT *,
              sum(weight) OVER(ORDER BY class, first_number)/sum(weight) OVER() AS band_end, 
              coalesce(sum(weight) OVER(ORDER BY class, first_number ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING),0)/sum(weight) OVER() AS band_start
        FROM weights_4;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('WEIGHTS', 'FINISH_CREATE_NEW_5', now(), found_rows());
      INSERT into proc_log(proc_name, step_name, ts) values ('WEIGHTS', 'START_CREATE_NEW_6', now());
      CREATE TABLE weights_new AS
      SELECT *,
            min(band_start) OVER(PARTITION BY class) AS class_band_start,
            max(band_end) OVER(PARTITION BY class) AS class_band_end
      FROM weights_5;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('WEIGHTS', 'FINISH_CREATE_NEW_6', now(), found_rows());
        CREATE INDEX idx_band_start ON weights_new (band_start);
        CREATE INDEX idx_band_end ON weights_new (band_end);
        ALTER TABLE weights RENAME to weights_old;
        ALTER TABLE weights_new RENAME to weights;
        DROP TABLE IF EXISTS weights_old;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('WEIGHTS', 'FINISH_INDEX_NEW', now(), found_rows());
      END IF;      
      DROP TABLE IF EXISTS weights_1;
      DROP TABLE IF EXISTS weights_2;
      DROP TABLE IF EXISTS weights_3;
      DROP TABLE IF EXISTS weights_4;
      DROP TABLE IF EXISTS weights_5;
      END;
      $$;"#).await?;
    // conn.simple_query(r"DROP EVENT IF EXISTS weights_event").await?;
    // conn.simple_query(r"CREATE EVENT weights_event 
    //                       ON SCHEDULE EVERY 24 HOUR STARTS FROM_UNIXTIME(CEILING(UNIX_TIMESTAMP(CURTIME())/86400)*86400 - 43200) 
    //                       DO
    //                       BEGIN
    //                         SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED;
    //                         CALL update_weights();
    //                         SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ;
    //                       END;").await?;
    Ok(())
  }
  
  async fn create_procedure_log(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(
      r"CREATE TABLE IF NOT EXISTS proc_log (
        id SERIAL PRIMARY KEY,
        proc_name varchar(40),
        step_name varchar(40),
        ts timestamp,
        rows_returned int
      )").await?;
    Ok(())
  }
  
}