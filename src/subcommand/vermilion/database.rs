use super::*;

pub async fn get_deadpool(settings: Settings) -> anyhow::Result<deadpool> {
  let mut deadpool_cfg = deadpool_postgres::Config::new();
  deadpool_cfg.host = settings.db_host().map(|s| s.to_string());
  deadpool_cfg.dbname = settings.db_name().map(|s| s.to_string());
  deadpool_cfg.user = settings.db_user().map(|s| s.to_string());
  deadpool_cfg.password = settings.db_password().map(|s| s.to_string());
  deadpool_cfg.manager = Some(ManagerConfig { recycling_method: RecyclingMethod::Fast });
  let deadpool = deadpool_cfg.create_pool(Some(deadpool_postgres::Runtime::Tokio1), NoTls)?;
  Ok(deadpool)
}

pub async fn initialize_runes_tables(pool: deadpool) -> anyhow::Result<()> {
  create_runes_table(pool).await?;
  Ok(())
}

pub async fn create_runes_table(pool: deadpool) -> anyhow::Result<()> {
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
    ").await?;
  Ok(())
}