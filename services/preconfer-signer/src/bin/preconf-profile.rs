use elementsplus_preconf::relay::Profile;
use std::{env, fs, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args_os()
        .nth(1)
        .ok_or("usage: preconf-profile PROFILE.json")?;
    let profile: Profile = serde_json::from_slice(&fs::read(Path::new(&path))?)?;
    println!("{}", profile.validate()?.id);
    Ok(())
}
