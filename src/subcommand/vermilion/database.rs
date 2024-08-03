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