use super::*;
use self::database;
use rust_decimal::Decimal;

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
  symbol: Option<char>,
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

      let init_result = database::initialize_runes_tables(pool.clone()).await;
      if init_result.is_err() {
        println!("Error initializing runes tables: {:?}", init_result.unwrap_err());
        return;
      }
      
      loop {
        let i = 0;
        let rune = match index.get_rune_by_number(i) {
          Ok(Some(rune)) => rune,
          Ok(None) => {
            println!("Rune number {} not found, pausing 60s", i);
            tokio::time::sleep(Duration::from_secs(60)).await;
            continue;
          },
          Err(err) => {
            println!("Error getting rune by number: {:?}, pausing 60s", err);
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
          burned: entry.burned.into(),
          divisibility: entry.divisibility as i64,
          etching: entry.etching.to_string(),
          mints: entry.mints.into(),
          number: entry.number as i64,
          premine: entry.premine.into(),
          spaced_rune: entry.spaced_rune.to_string(),
          unspaced_rune: entry.spaced_rune.rune.to_string(),
          rune_u128: entry.spaced_rune.rune.0.to_string(),
          spacers: entry.spaced_rune.spacers as i64,
          symbol: entry.symbol,
          mint_amount: entry.terms.and_then(|t| t.amount.map(Into::into)),
          mint_cap: entry.terms.and_then(|t| t.cap.map(Into::into)),
          mint_height_lower: entry.terms.and_then(|t| t.height.0.map(|h| h as i64)),
          mint_height_upper: entry.terms.and_then(|t| t.height.1.map(|h| h as i64)),
          mint_offset_lower: entry.terms.and_then(|t| t.offset.0.map(|o| o as i64)),
          mint_offset_upper: entry.terms.and_then(|t| t.offset.1.map(|o| o as i64)),
          timestamp: entry.timestamp as i64,
          turbo: entry.turbo,
          parent: parent.map(|p| p.to_string()),
        };
      }

    });

  });

  return runes_indexer_thread;
}