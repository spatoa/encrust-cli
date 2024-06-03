mod key_management;
mod encryption;
mod decryption;

use clap::{Parser, Subcommand, ValueEnum};
use encryption::encrypt_file;
use decryption::decrypt_file;
use key_management::generate_key;

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
            println!("Encrypting file: {}", input_file);
            println!("Using algorithm: {:?}", algorithm);

            let key = key.as_deref().unwrap_or("");
            let output_file = output_file.as_deref().unwrap_or("");

            // Call the encrypt function here
            encrypt_file(&input_file, Some(output_file), key, *algorithm)
        }
        Commands::Decrypt { input_file, output_file, algorithm, key } => {
            println!("Decrypting file: {}", input_file);
            println!("Using algorithm: {:?}", algorithm);

            let key = key.as_deref().unwrap_or("");
            let output_file = output_file.as_deref().unwrap_or("");

            // Call the decrypt function here
            decrypt_file(&input_file, Some(output_file), key, *algorithm)
        }
    }
}
