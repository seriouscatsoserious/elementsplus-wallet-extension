use elementsplus_preconf::operator::Config;
use serde::Serialize;
use std::{env, fs, path::Path};

#[derive(Serialize)]
struct FundingTemplate<'a> {
    version: u32,
    script_pubkey: String,
    raw_descriptor: String,
    asset: String,
    amount_atomic: u64,
    operator_config: &'a Config,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args_os()
        .nth(1)
        .ok_or("usage: preconf-bond OPERATOR_CONFIG.json")?;
    let config: Config = serde_json::from_slice(&fs::read(Path::new(&path))?)?;
    let bond = config.compile()?;
    let script = hex::encode(bond.script_pubkey().as_bytes());
    let template = FundingTemplate {
        version: 1,
        raw_descriptor: format!("raw({script})"),
        script_pubkey: script,
        asset: config.fee_asset.to_string(),
        amount_atomic: config.collateral,
        operator_config: &config,
    };
    println!("{}", serde_json::to_string_pretty(&template)?);
    Ok(())
}
