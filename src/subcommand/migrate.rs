use super::*;
use crate::index::fetcher;
use crate::index::entry::InscriptionEntry;

use std::error::Error;
use mysql_async::Pool;
use mysql_async::Params;
use mysql_async::params;
use mysql_async::prelude::Queryable;

#[derive(Debug, Parser, Clone)]
pub(crate) struct Migrator {
  #[arg(
    long,
    help = "Which migration to run. If not specified, all migrations will be run."
  )]
  pub(crate) script_number: u16,
}

#[derive(Clone, Serialize)]
pub struct Metadata {
  id: String,
  is_bitmap_style: bool,
}

impl Migrator {
  pub(crate) fn run(&self, options: Options) -> SubcommandResult {
    if self.script_number == 1 {
      match Self::migrate_is_bitmap_style(options) {
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

  fn migrate_is_bitmap_style(options: Options) -> Result<(), Box<dyn Error>> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let result: Result<(), Box<dyn Error>> = rt.block_on(async {
      let index = Arc::new(Index::open(&options)?);
      let config = options.load_config()?;
      let url = config.db_connection_string.unwrap();
      let pool = Pool::new(url.as_str());
      let mut number = 0;
      let batch_size = 10000;
      let fetcher =  match fetcher::Fetcher::new(&options) {
        Ok(fetcher) => fetcher,
        Err(e) => {
          println!("Error creating fetcher: {:?}, exiting", e);
          return Err(e.into())
        }
      };
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
        let t32 = Instant::now();
        for (entry, inscription) in entry_inscription_pairs {
          let mut i =0;
          let s0 = Instant::now();
          let is_bitmap_style = Self::extract_bitmap_style(inscription, re.clone())?;
          let s1 = Instant::now();
          let metadata = Metadata {
            id: entry.id.to_string(),
            is_bitmap_style: is_bitmap_style
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
        let _exec = Self::bulk_update_bitmap_style(pool.clone(), metadata_vec).await;
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

  fn extract_bitmap_style(inscription: Inscription, re: Regex) -> Result<bool, Box<dyn Error>> {
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

  async fn _get_conn(pool: mysql_async::Pool) -> Result<mysql_async::Conn, mysql_async::Error> {
    let conn = pool.get_conn().await;
    conn
  }

  async fn bulk_insert_update<F, P, T>(
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

  pub(crate) async fn bulk_update_bitmap_style(pool: mysql_async::Pool, metadata_vec: Vec<Metadata>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut _exec = Self::bulk_insert_update(pool.clone(),
      "ordinals".to_string(),
      vec![
        "id".to_string(),
        "is_bitmap_style".to_string()
      ],
      vec![
        "is_bitmap_style".to_string()
      ],
      metadata_vec.clone(),
      |metadata| params! { 
        "id" => &metadata.id,
        "is_bitmap_style" => &metadata.is_bitmap_style
      }
    ).await;
    Ok(_exec?)
  }

}