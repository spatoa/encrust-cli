mod key_management;
mod encryption;
mod decryption;

use clap::{Parser, Subcommand, ValueEnum};
use encryption::encrypt_file;
use decryption::decrypt_file;
use key_management::{generate_key, load_key_from_file, save_key_to_file};

#[derive(Parser)]
#[command(name = "encrust")]
#[command(author = "Lachlan  Burns (@spatoa)")]
#[command(version = "1.0")]
#[command(about = "Encrypts and decrypts files using various encryption algorithms")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt {
        #[arg(value_name = "INPUT_FILE")]
        input_file: String,

        #[arg(value_name = "OUTPUT_FILE")]
        output_file: Option<String>,

        #[arg(short, long, value_name = "ALGORITHM", value_enum, default_value_t = Algorithm::Aes)]
        algorithm: Algorithm,

        #[arg(short, long, value_name = "KEY")]
        key: Option<String>,
    },
    Decrypt {
        #[arg(value_name = "INPUT_FILE")]
        input_file: String,

        #[arg(value_name = "OUTPUT_FILE")]
        output_file: Option<String>,

        #[arg(short, long, value_name = "ALGORITHM", value_enum, default_value_t = Algorithm::Aes)]
        algorithm: Algorithm,

        #[arg(short, long, value_name = "KEY")]
        key: Option<String>,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Algorithm {
    Aes,
    Chacha,
}

fn main() {
    let args = Cli::parse();

    match &args.command {
        Commands::Encrypt { input_file, output_file, algorithm, key } => {
            let key = if let Some(key_path) = key {
                load_key_from_file(key_path).expect("Failed to load key")
            } else {
                let generated_key = generate_key();
                // Save the generated key to a file for future use
                let key_file_path = "generated_key.key"; // You can customize this path
                save_key_to_file(&generated_key, key_file_path).expect("Failed to save generated key");
                println!("Generated key saved to: {}", key_file_path);
                generated_key.to_vec()
            };

            println!("Encrypting file: {}", input_file);
            println!("Using algorithm: {:?}", algorithm);
            println!("Using key: {:?}", key);

            let output_file = output_file.as_deref().unwrap_or("");

            // Call the encrypt function here
            encrypt_file(&input_file, Some(output_file), key, *algorithm)
        }
        Commands::Decrypt { input_file, output_file, algorithm, key } => {
            let key = if let Some(key_path) = key {
                load_key_from_file(key_path).expect("Failed to load key")
            } else {
                panic!("A key is required for decryption");
            };

            println!("Decrypting file: {}", input_file);
            println!("Using algorithm: {:?}", algorithm);
            println!("Using key: {:?}", key);

            let output_file = output_file.as_deref().unwrap_or("");

            // Call the decrypt function here
            decrypt_file(&input_file, Some(output_file), key, *algorithm)
        }
    }
}
