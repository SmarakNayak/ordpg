use super::*;
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

pub async fn process_runes(index: Arc<Index>, tx: &deadpool_postgres::Transaction<'_>, block_number: u32) -> anyhow::Result<()> {
  let start_time = Instant::now();
  let spaced_runes = index.get_runes_in_block(block_number as u64)
    .with_context(|| format!("Error getting runes in block {}", block_number))?;
  if spaced_runes.is_empty() {
    log::info!("No runes found in block {}, indexing next block", block_number);
    return Ok(());
  }
  let len = spaced_runes.len();
  let mut rows = Vec::new();
  for spaced_rune in spaced_runes {
    let full_rune = index.rune(spaced_rune.rune)
      .with_context(|| format!("Error getting full rune for rune {}", spaced_rune.rune))?
      .ok_or_else(|| anyhow::anyhow!("Rune number {} not found", spaced_rune.rune))?;
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
    rows.push(row);
  }
  bulk_insert_runes(&tx, rows).await
    .with_context(|| format!("Error bulk inserting runes for block {}", block_number))?;
  let elapsed = start_time.elapsed();
  log::info!("Block {}: Indexed {} runes in {:?}", block_number, len, elapsed);
  Ok(())
}
pub async fn initialize_runes_tables(pool: deadpool) -> anyhow::Result<()> {
  create_runes_table(pool).await.context("Error creating runes table")?;
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
      spaced_rune varchar(100),
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

async fn bulk_insert_runes(tx: &deadpool_postgres::Transaction<'_>, data: Vec<RuneRow>) -> anyhow::Result<()> {
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
  let sink = tx.copy_in(copy_stm).await?;
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
  let _x = writer.finish().await?;
  //println!("Finished writing metadata: {:?}", x);
  Ok(())
}

fn u128_to_decimal(u: u128) -> Decimal {
  let decimal = Decimal::from_u128(u);
  // return -1 if it overflows beyond 96 bits -- look into bigdecimal package if 128bit really needed
  decimal.unwrap_or(Decimal::from(-1))
}