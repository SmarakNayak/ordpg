use super::*;
use self::database;
use rust_decimal::{prelude::FromPrimitive, Decimal};

pub struct RuneRow {
  block: i64,
  tx_index: i64,
  burned: Decimal,
  divisibility: i64,
  etching: String,
  mints: Decimal,
  number: i64,
  premine: Decimal,
  spaced_rune: String,
  unspaced_rune: String,
  rune_u128: String,
  spacers: i64,
  symbol: Option<String>,
  mint_amount: Option<Decimal>,
  mint_cap: Option<Decimal>,
  mint_height_lower: Option<i64>,
  mint_height_upper: Option<i64>,
  mint_offset_lower: Option<i64>,
  mint_offset_upper: Option<i64>,
  timestamp: i64,
  turbo: bool,
  parent: Option<String>,
}

pub fn run_runes_indexer(settings: Settings, index: Arc<Index>) -> JoinHandle<()> {
  println!("Running runes indexer");
  //CODE GOES HERE
  let runes_indexer_thread = thread::spawn(move ||{
    let rt = tokio::runtime::Builder::new_multi_thread()
      .enable_all()
      .build()
      .unwrap();

    rt.block_on(async move {
      let pool = match database::get_deadpool(settings.clone()).await {
        Ok(deadpool) => deadpool,
        Err(err) => {
          println!("Error creating deadpool: {:?}", err);
          return;
        }
      };

      let init_result = initialize_runes_tables(pool.clone()).await;
      if init_result.is_err() {
        println!("Error initializing runes tables: {:?}", init_result.unwrap_err());
        return;
      }
      
      
      let mut i = match get_start_rune_number(pool.clone()).await {
        Ok(start_number) => start_number as usize,
        Err(err) => {
          println!("Error getting start rune number: {:?}", err);
          return;
        }
      };
      log::info!("Starting rune indexing at number: {}", i);
      let mut elapsed = Duration::from_secs(0);
      loop {
        // break if ctrl-c is received
        if SHUTTING_DOWN.load(atomic::Ordering::Relaxed) {
          break;
        }

        let start_time = Instant::now();
        let rune = match index.get_rune_by_number(i) {
          Ok(Some(rune)) => rune,
          Ok(None) => {
            println!("Rune number {} not found, pausing 60s", i);
            tokio::time::sleep(Duration::from_secs(60)).await;
            continue;
          },
          Err(err) => {
            println!("Error getting rune for number {}: {:?}, pausing 60s", i, err);
            tokio::time::sleep(Duration::from_secs(60)).await;
            continue;
          }
        };

        let full_rune = match index.rune(rune) {
          Ok(Some(full_rune)) => full_rune,
          Ok(None) => {
            println!("Rune number {} not found, pausing 60s", i);
            tokio::time::sleep(Duration::from_secs(60)).await;
            continue;
          },
          Err(err) => {
            println!("Error getting full rune: {:?}, pausing 60s", err);
            tokio::time::sleep(Duration::from_secs(60)).await;
            continue;
          }
        };

        let (id, entry, parent) = full_rune;
        let row = RuneRow {
          block: id.block as i64,
          tx_index: id.tx as i64,
          burned: u128_to_decimal(entry.burned),
          divisibility: entry.divisibility as i64,
          etching: entry.etching.to_string(),
          mints: u128_to_decimal(entry.mints),
          number: entry.number as i64,
          premine: u128_to_decimal(entry.premine),
          spaced_rune: entry.spaced_rune.to_string(),
          unspaced_rune: entry.spaced_rune.rune.to_string(),
          rune_u128: entry.spaced_rune.rune.0.to_string(),
          spacers: entry.spaced_rune.spacers as i64,
          symbol: entry.symbol.and_then(|s| Some(s.to_string())),
          mint_amount: entry.terms.and_then(|t| t.amount.map(|a| u128_to_decimal(a))),
          mint_cap: entry.terms.and_then(|t| t.cap.map(|c| u128_to_decimal(c))),
          mint_height_lower: entry.terms.and_then(|t| t.height.0.map(|h| h as i64)),
          mint_height_upper: entry.terms.and_then(|t| t.height.1.map(|h| h as i64)),
          mint_offset_lower: entry.terms.and_then(|t| t.offset.0.map(|o| o as i64)),
          mint_offset_upper: entry.terms.and_then(|t| t.offset.1.map(|o| o as i64)),
          timestamp: entry.timestamp as i64,
          turbo: entry.turbo,
          parent: parent.map(|p| p.to_string()),
        };
        
        let rows = vec![row];
        let insert_result = bulk_insert_runes(pool.clone(), rows).await;
        if insert_result.is_err() {
          println!("Error bulk inserting runes: {:?}", insert_result.unwrap_err());
          tokio::time::sleep(Duration::from_secs(60)).await;
          continue;
        }

        i += 1;

        elapsed += start_time.elapsed();
        if i % 100 == 0 {
          log::info!("Indexed {} runes in {:?}", i, elapsed);
          elapsed = Duration::from_secs(0);
        }

      }

    });

  });

  return runes_indexer_thread;
}

async fn initialize_runes_tables(pool: deadpool) -> anyhow::Result<()> {
  create_runes_table(pool).await?;
  Ok(())
}

async fn create_runes_table(pool: deadpool) -> anyhow::Result<()> {
  let conn = pool.get().await?;
  conn.simple_query(r"
    CREATE TABLE IF NOT EXISTS runes (
      block bigint not null,
      tx_index bigint not null,
      burned NUMERIC(39, 0),
      divisibility bigint,
      etching varchar(80),
      mints NUMERIC(39, 0),
      number bigint,
      premine NUMERIC(39, 0),
      spaced_rune varchar(50),
      unspaced_rune varchar(40),
      rune_u128 varchar(39),
      spacers bigint,
      symbol varchar(1),
      mint_amount NUMERIC(39, 0),
      mint_cap NUMERIC(39, 0),
      mint_height_lower bigint,
      mint_height_upper bigint,
      mint_offset_lower bigint,
      mint_offset_upper bigint,
      timestamp bigint,
      turbo boolean,
      parent varchar(80),
      CONSTRAINT block_tx_key PRIMARY KEY (block, tx_index)
    )").await?;
  conn.simple_query(r"
    CREATE INDEX IF NOT EXISTS index_runes_parent ON runes (parent);
    CREATE INDEX IF NOT EXISTS index_runes_spaced_rune ON runes (spaced_rune);
    CREATE INDEX IF NOT EXISTS index_runes_number ON runes (number);
    CREATE INDEX IF NOT EXISTS index_runes_etching ON runes (etching);
    ").await?;
  Ok(())
}

async fn bulk_insert_runes(pool: deadpool, data: Vec<RuneRow>) -> anyhow::Result<()> {
  let conn = pool.get().await?;
  let copy_stm = r#"COPY runes (
    block,
    tx_index,
    burned,
    divisibility,
    etching,
    mints,
    number,
    premine,
    spaced_rune,
    unspaced_rune,
    rune_u128,
    spacers,
    symbol,
    mint_amount,
    mint_cap,
    mint_height_lower,
    mint_height_upper,
    mint_offset_lower,
    mint_offset_upper,
    timestamp,
    turbo,
    parent
  ) FROM STDIN BINARY"#;
  let col_types = vec![
    Type::INT8,
    Type::INT8,
    Type::NUMERIC,
    Type::INT8,
    Type::VARCHAR,
    Type::NUMERIC,
    Type::INT8,
    Type::NUMERIC,
    Type::VARCHAR,
    Type::VARCHAR,
    Type::VARCHAR,
    Type::INT8,
    Type::VARCHAR,
    Type::NUMERIC,
    Type::NUMERIC,
    Type::INT8,
    Type::INT8,
    Type::INT8,
    Type::INT8,
    Type::INT8,
    Type::BOOL,
    Type::VARCHAR,
  ];
  let sink = conn.copy_in(copy_stm).await?;
  let writer = BinaryCopyInWriter::new(sink, &col_types);
  pin_mut!(writer);
  for m in data {
    let mut row: Vec<&'_ (dyn ToSql + Sync)> = Vec::new();
    row.push(&m.block);
    row.push(&m.tx_index);
    row.push(&m.burned);
    row.push(&m.divisibility);
    row.push(&m.etching);
    row.push(&m.mints);
    row.push(&m.number);
    row.push(&m.premine);
    row.push(&m.spaced_rune);
    row.push(&m.unspaced_rune);
    row.push(&m.rune_u128);
    row.push(&m.spacers);
    let clean_symbol = &m.symbol.map(|s| s.replace("\0", ""));
    row.push(clean_symbol);
    row.push(&m.mint_amount);
    row.push(&m.mint_cap);
    row.push(&m.mint_height_lower);
    row.push(&m.mint_height_upper);
    row.push(&m.mint_offset_lower);
    row.push(&m.mint_offset_upper);
    row.push(&m.timestamp);
    row.push(&m.turbo);
    row.push(&m.parent);
    writer.as_mut().write(&row).await?;
  }
  let x = writer.finish().await?;
  println!("Finished writing metadata: {:?}", x);
  Ok(())
}

async fn get_start_rune_number(pool: deadpool) -> anyhow::Result<i64> {
  let conn = pool.get().await?;
  let row = conn.query_one("SELECT MAX(number) FROM runes", &[]).await?;
  let last_number: Option<i64> = row.get(0);
  let start_number = last_number.and_then(|n| Some(n + 1)).unwrap_or(0);
  Ok(start_number)
}

fn u128_to_decimal(u: u128) -> Decimal {
  let decimal = Decimal::from_u128(u);
  // return -1 if it overflows beyond 96 bits -- look into bigdecimal package if 128bit really needed
  decimal.unwrap_or(Decimal::from(-1))
}