use super::*;

#[derive(Debug, Parser, Clone)]
pub(crate) struct Migrator {
  #[arg(
    long,
    help = "Which migration to run. If not specified, all migrations will be run."
  )]
  pub(crate) script_number: u16,
}

impl Migrator {
  pub(crate) fn run(&self, _options: Options, _index: Arc<Index>) -> SubcommandResult {
    if self.script_number == 1 {
      println!("Running test migration 1");
      //CODE GOES HERE
      Ok(None)
    } else {
      Ok(None)
    }
  }

}