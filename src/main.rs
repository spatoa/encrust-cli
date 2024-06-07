mod decryption;
mod encryption;

use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::process;

use clap::{Parser, Subcommand, ValueEnum};
use decryption::decrypt_ciphertext;
use encryption::encrypt_plaintext;

const ERROR_FILE_NOT_FOUND: i32 = 1;
const ERROR_PERMISSION_DENIED: i32 = 2;
const ERROR_UNKNOWN: i32 = 3;
const ERROR_CREATE_FILE_FAIL: i32 = 4;
const ERROR_READ_FILE: i32 = 5;
const ERROR_WRITE_TO_FILE: i32 = 7;

#[derive(Parser)]
#[command(name = "encrust")]
#[command(version)]
#[command(about = "Encrypts and decrypts files using various encryption algorithms")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt {
        #[arg(value_name = "INPUT_FILE_PATH")]
        input_file_path: String,

        #[arg(value_name = "OUTPUT_FILE_PATH")]
        output_file_path: Option<String>,

        #[arg(short, long, value_name = "ALGORITHM", value_enum, default_value_t = Algorithm::Aes)]
        algorithm: Algorithm,

        #[arg(short, long, value_name = "KEY")]
        key_file_path: Option<String>,
    },
    Decrypt {
        #[arg(value_name = "INPUT_FILE_PATH")]
        input_file_path: String,

        #[arg(value_name = "OUTPUT_FILE_PATH")]
        output_file_path: Option<String>,

        #[arg(short, long, value_name = "ALGORITHM", value_enum, default_value_t = Algorithm::Aes)]
        algorithm: Algorithm,

        #[arg(short, long, value_name = "KEY")]
        key_file_path: Option<String>,
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
        Commands::Encrypt {
            input_file_path,
            output_file_path,
            algorithm,
            key_file_path,
        } => {
            println!("\nEncrypting file: {}", input_file_path);

            // Create output file at user entered or default file path
            let default_output_file_path = format!("{}_encrypted", input_file_path);
            let output_file_path = output_file_path
                .as_deref()
                .unwrap_or_else(|| default_output_file_path.as_str());
            let mut output_file = create_file(&output_file_path);

            // Read and encrypt file
            let input_file_contents = read_file(&input_file_path);
            let ciphertext = encrypt_plaintext(input_file_contents, *algorithm);

            // Write ciphertext to file
            match output_file.write_all(&ciphertext) {
                Ok(output_file) => output_file,
                Err(e) => {
                    eprintln!("Error: Failed to write to file {}: {}", output_file_path, e);
                    process::exit(ERROR_WRITE_TO_FILE)
                }
            }
            match output_file.flush() {
                Ok(output_file) => output_file,
                Err(e) => {
                    eprintln!("Error: Failed to flush file {}: {}", output_file_path, e);
                    process::exit(ERROR_UNKNOWN)
                }
            }

            process::exit(0)
        }
        Commands::Decrypt {
            input_file_path,
            output_file_path,
            algorithm,
            key_file_path,
        } => {
            println!("\nDecrypting file: {}", input_file_path);

            // Create output file at user entered or default file path
            let default_output_file_path = format!("{}_decrypted", input_file_path);
            let output_file_path = output_file_path
                .as_deref()
                .unwrap_or_else(|| default_output_file_path.as_str());
            let mut output_file = create_file(&output_file_path);

            // Read and decrypt file
            let input_file_contents = read_file(&input_file_path);
            let plaintext = decrypt_ciphertext(input_file_contents, *algorithm);

            // Write ciphertext to file
            match output_file.write_all(&plaintext) {
                Ok(output_file) => output_file,
                Err(e) => {
                    eprintln!("Error: Failed to write to file {}: {}", output_file_path, e);
                    process::exit(ERROR_WRITE_TO_FILE)
                }
            }
            match output_file.flush() {
                Ok(output_file) => output_file,
                Err(e) => {
                    eprintln!("Error: Failed to flush file {}: {}", output_file_path, e);
                    process::exit(ERROR_UNKNOWN)
                }
            }

            process::exit(0)
        }
    }
}

/// Opens a file based off of a given filename.
fn open_file(filename: &str) -> File {
    match File::open(filename) {
        Ok(file) => file,
        Err(e) => {
            // Handle different kinds of errors separately
            process::exit(match e.kind() {
                ErrorKind::NotFound => {
                    eprintln!("Error: File not found - {}", filename);
                    ERROR_FILE_NOT_FOUND
                }
                ErrorKind::PermissionDenied => {
                    eprintln!("Error: Permission denied - {}", filename);
                    ERROR_PERMISSION_DENIED
                }
                _ => {
                    eprintln!("Error: Failed to open file {}: {}", filename, e);
                    ERROR_UNKNOWN
                }
            })
        }
    }
}

/// Reads the contents of a file as raw bytes into a vector.
fn read_file(filename: &str) -> Vec<u8> {
    let mut file = open_file(filename);
    let mut contents = Vec::new();

    if let Err(e) = file.read_to_end(&mut contents) {
        eprintln!("Error: Failed to read file {}: {}", filename, e);
        process::exit(ERROR_READ_FILE); // Read error
    }

    contents
}

/// Creates a file with a given filename.
fn create_file(filename: &str) -> File {
    match File::create(filename) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Error: Failed to create file {}: {}", filename, e);
            process::exit(ERROR_CREATE_FILE_FAIL); // Exit the program with a non-zero exit code to indicate an error
        }
    }
}
