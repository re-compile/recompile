//! Generate default configuration file

use re_rules::config::generate_default_config;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = "re.toml";
    generate_default_config(config_path)?;
    println!("Generated default configuration at {}", config_path);
    Ok(())
}
