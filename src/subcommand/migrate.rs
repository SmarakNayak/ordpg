use super::*;
use crate::index::entry::InscriptionEntry;

use std::error::Error;
use mysql_async::Pool;
use mysql_async::params;
use mysql_async::prelude::Queryable;
use mysql_async::TxOpts;

#[derive(Debug, Parser, Clone)]
pub(crate) struct Migrator {
  #[arg(
    long,
    help = "Which migration to run. If not specified, all migrations will be run."
  )]
  pub(crate) script_number: u16,
}

#[derive(Clone, Serialize)]
pub struct UpdateMetadata {
  id: String,
  is_bitmap_style: bool,
  charms: u16,
  delegate: Option<String>,
  content_encoding: Option<String>,
}

impl Migrator {
  pub(crate) fn run(&self, options: Options, index: Arc<Index>) -> SubcommandResult {
    if self.script_number == 1 {
      match Self::migrate_new_fields(options, index) {
        Ok(_) => {
          println!("Migration complete");
        },
        Err(e) => {
          println!("Error running migration: {:?}", e);
        }
      }
      Ok(None)
    } else {
      Ok(None)
    }
  }

  pub fn migrate_new_fields(options: Options, index: Arc<Index>) -> Result<(), Box<dyn Error>> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let result: Result<(), Box<dyn Error>> = rt.block_on(async {
      let config = options.load_config()?;
      let url = config.db_connection_string.unwrap();
      let pool = Pool::new(url.as_str());
      let mut number = 0;
      let batch_size = 10000;
      match Self::add_table_cols(pool.clone()).await {
        Ok(_) => {},
        Err(e) => {
          log::warn!("Error adding table columns: {:?}", e);
        }
      }
      
      loop {
        if SHUTTING_DOWN.load(atomic::Ordering::Relaxed) {
          break;
        }
        //1. Get entries
        let t0 = Instant::now();
        let mut inscription_entries = Vec::new();
        for i in number..number+batch_size {
          let inscription_entry = index.get_inscription_entry_by_sequence_number(i).unwrap();
          let inscription_entry = match inscription_entry {
            Some(inscription_entry) => {
              inscription_entry
            },
            None => {
              log::info!("No inscription found for sequence number: {}. Breaking from loop, sleeping a minute", number);
              break;
            }
          };
          inscription_entries.push(inscription_entry);
        }
        if inscription_entries.len() == 0 {
          log::info!("No inscription found for sequence number: {}. Marking as not found. Breaking from loop, sleeping a minute", number);
          tokio::time::sleep(Duration::from_secs(60)).await;
          continue;
        }
        
        //2. Get Transactions
        let t1 = Instant::now();
        let mut txs = Vec::new();
        for entry in inscription_entries.clone() {
          let tx = match index.get_transaction(entry.id.txid) {
            Ok(tx) => {
              match tx {
                Some(tx) => {
                  tx
                },
                None => {
                  log::info!("No transaction found for txid: {:?}. Breaking from loop, sleeping a minute", entry.id.txid);
                  break;
                }
              }
            }
            Err(e) => {
              log::info!("Error getting transaction for txid: {:?}, error: {:?}", entry.id.txid, e);
              break;
            }
          };
          txs.push(tx);
        }
        //3. Get Inscriptions
        let t2 = Instant::now();
        let ids: Vec<InscriptionId> = inscription_entries.clone().into_iter().map(|x| x.id).collect();
        let id_txs: Vec<_> = ids.into_iter().zip(txs.into_iter()).collect();
        let mut inscriptions: Vec<Inscription> = Vec::new();
        for (inscription_id, tx) in id_txs {
          let inscription = ParsedEnvelope::from_transaction(&tx)
            .into_iter()
            .nth(inscription_id.index as usize)
            .map(|envelope| envelope.payload)
            .unwrap();
          inscriptions.push(inscription);
        }

        //4. Extract bitmap style
        let t3 = Instant::now();
        let entry_inscription_pairs: Vec<(InscriptionEntry, Inscription)> = inscription_entries.into_iter().zip(inscriptions.into_iter()).collect();
        let mut metadata_vec = Vec::new();
        let pattern = r"^[^ \n]+[.][^ \n]+$";
        let re = regex::Regex::new(pattern).unwrap();
        for (entry, inscription) in entry_inscription_pairs {
          let mut i =0;
          let s0 = Instant::now();
          let is_bitmap_style = Self::extract_bitmap_style(&inscription, re.clone())?;
          let delegate = match inscription.delegate() {
            Some(delegate) => delegate.to_string(),
            None => "".to_string()
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
          let s1 = Instant::now();
          let metadata = UpdateMetadata {
            id: entry.id.to_string(),
            is_bitmap_style: is_bitmap_style,
            charms: entry.charms,
            delegate: inscription.delegate().map(|x| x.to_string()),
            content_encoding: content_encoding,
          };
          let s2 = Instant::now();
          metadata_vec.push(metadata);
          let s3 = Instant::now();
          i+=1;
          if i % 1000 == 0{
            log::info!("Time to extract bitmap style: {:?}, Time to create metadata: {:?}, Time to push metadata: {:?}", s1.duration_since(s0), s2.duration_since(s1), s3.duration_since(s2));
          }
        }

        //4. Save to db
        let t4 = Instant::now();
        let _exec = Self::bulk_update_metadata(pool.clone(), metadata_vec).await;
        let t5 = Instant::now();
        match _exec {
          Ok(_) => {
            log::info!("Success updating bitmap style starting from {}", number);
            log::info!("Time to get entries: {:?}, Time to get transactions: {:?}, Time to get inscriptions: {:?}, Time to extract bitmap style: {:?}, Time to save to db: {:?}", t1.duration_since(t0), t2.duration_since(t1), t3.duration_since(t2), t4.duration_since(t3), t5.duration_since(t4));
            number += batch_size;
          },
          Err(e) => {
            log::info!("Error updating bitmap style starting from {}: {:?}", number, e);
            log::info!("Time to get entries: {:?}, Time to get transactions: {:?}, Time to get inscriptions: {:?}, Time to extract bitmap style: {:?}, Time to save to db: {:?}", t1.duration_since(t0), t2.duration_since(t1), t3.duration_since(t2), t4.duration_since(t3), t5.duration_since(t4));
            tokio::time::sleep(Duration::from_secs(60)).await;
            continue;
          }
            
        }
      }
      Ok(())
    });
    result
  }

  fn extract_bitmap_style(inscription: &Inscription, re: Regex) -> Result<bool, Box<dyn Error>> {
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
    let is_bitmap_style = match text.clone() {
      Some(text) => re.is_match(&text),
      None => false
    };
    Ok(is_bitmap_style)
  }

  async fn get_conn(pool: mysql_async::Pool) -> Result<mysql_async::Conn, mysql_async::Error> {
    let conn = pool.get_conn().await;
    conn
  }

  async fn bulk_update_metadata(pool: mysql_async::Pool, metadata_vec: Vec<UpdateMetadata>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut conn = Self::get_conn(pool).await?;
    let mut tx = conn.start_transaction(TxOpts::default()).await?;
    let _exec = tx.exec_batch(
      r"UPDATE ordinals set is_bitmap_style = :is_bitmap_style, charms = :charms, delegate = :delegate, content_encoding = :content_encoding where id = :id",
        metadata_vec.iter().map(|metadata| params! {
          "is_bitmap_style" => &metadata.is_bitmap_style,
          "id" => &metadata.id,
          "charms" => &metadata.charms,
          "delegate" => &metadata.delegate,
          "content_encoding" => &metadata.content_encoding,
      })
    ).await;
    match _exec {
      Ok(_) => {},
      Err(error) => {
        log::warn!("Error bulk updating metadata: {}", error);
        return Err(Box::new(error));
      }
    };
    let result = tx.commit().await;
    match result {
      Ok(_) => Ok(()),
      Err(error) => {
        log::warn!("Error bulk committing ordinal metadata: {}", error);
        Err(Box::new(error))
      }
    }
  }

  async fn add_table_cols(pool: mysql_async::Pool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut conn = Self::get_conn(pool).await?;
    let mut tx = conn.start_transaction(TxOpts::default()).await?;
    let _exec = tx.query_drop(
      r"ALTER TABLE ordinals ADD COLUMN charms SMALLINT"
    ).await;
    match _exec {
      Ok(_) => {},
      Err(error) => {
        log::warn!("Error adding charms column: {}", error);
        return Err(Box::new(error));
      }
    };
    let _exec = tx.query_drop(
      r"ALTER TABLE ordinals ADD COLUMN delegate varchar(80)"
    ).await;
    match _exec {
      Ok(_) => {},
      Err(error) => {
        log::warn!("Error adding delegate column: {}", error);
        return Err(Box::new(error));
      }
    };
    let _exec = tx.query_drop(
      r"ALTER TABLE ordinals ADD COLUMN content_encoding TEXT"
    ).await;
    match _exec {
      Ok(_) => {},
      Err(error) => {
        log::warn!("Error adding content_encoding column: {}", error);
        return Err(Box::new(error));
      }
    };
    let result = tx.commit().await;
    match result {
      Ok(_) => Ok(()),
      Err(error) => {
        log::warn!("Error committing ordinal metadata: {}", error);
        Err(Box::new(error))
      }
    }
  }
}