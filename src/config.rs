use super::*;

#[derive(Deserialize, Default, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
  pub(crate) hidden: HashSet<InscriptionId>,
  pub(crate) bitcoin_rpc_pass: Option<String>,
  pub(crate) bitcoin_rpc_user: Option<String>,
  pub(crate) db_connection_string: Option<String>,
  pub(crate) db_host: Option<String>,
  pub(crate) db_name: Option<String>,
  pub(crate) db_user: Option<String>,
  pub(crate) db_password: Option<String>,
  pub(crate) start_number_override: Option<u64>,
  pub(crate) s3_bucket_name: Option<String>,
  pub(crate) s3_upload_start_number: Option<u64>,
  pub(crate) s3_head_check: Option<bool>
}

impl Config {
  pub(crate) fn is_hidden(&self, inscription_id: InscriptionId) -> bool {
    self.hidden.contains(&inscription_id)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn inscriptions_can_be_hidden() {
    let a = "8d363b28528b0cb86b5fd48615493fb175bdf132d2a3d20b4251bba3f130a5abi0"
      .parse::<InscriptionId>()
      .unwrap();

    let b = "8d363b28528b0cb86b5fd48615493fb175bdf132d2a3d20b4251bba3f130a5abi1"
      .parse::<InscriptionId>()
      .unwrap();

    let config = Config {
      hidden: iter::once(a).collect(),
      ..Default::default()
    };

    assert!(config.is_hidden(a));
    assert!(!config.is_hidden(b));
  }

  #[test]
  fn example_config_file_is_valid() {
    let _: Config = serde_yaml::from_reader(File::open("ord.yaml").unwrap()).unwrap();
  }
}
