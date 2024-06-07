mod encryption;
mod decryption;

use std::fs::{File, read, write};
use std::io::{self, ErrorKind, BufRead, BufReader, Read, Write};
use std::process;

use chacha20poly1305::Error;
use clap::{Parser, Subcommand, ValueEnum};
use encryption::encrypt_file;
use decryption::decrypt_file;

const ERROR_FILE_NOT_FOUND: i32 = 1;
const ERROR_PERMISSION_DENIED: i32 = 2;
const ERROR_UNKNOWN: i32 = 3;
const ERROR_CREATE_FILE_FAIL: i32 = 4;
const ERROR_READ_FILE: i32 = 5;

#[derive(Parser)]
#[command(name = "encrust")]
#[command(author = "Lachlan  Burns (@spatoa)")]
#[command(version = "0.1.0")]
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
        Commands::Encrypt { input_file_path, output_file_path, algorithm, key_file_path } => {
            println!("\nEncrypting file: {}", input_file_path);

            // File handling
            let output_file_path = output_file_path.as_deref().unwrap_or("test_encrypt.txt");

            let input_file_contents = read_file(&input_file_path);

            let output_file = create_file(&output_file_path);

            encrypt_file(input_file_contents, *algorithm, output_file_path);
        }
        Commands::Decrypt { input_file_path, output_file_path, algorithm, key_file_path } => {
            println!("\nDecrypting file: {}", input_file_path);

            // File handling
            let output_file_path = output_file_path.as_deref().unwrap_or("test_decrypt.txt");

            let input_file_contents = read_file(&input_file_path);

            let output_file = create_file(&output_file_path);

            decrypt_file(input_file_contents, *algorithm, output_file_path);
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

/// Creates a file with a given filename.
fn create_file(filename: &str) -> File {
    match File::create(filename) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Error: Failed to create file {}: {}", filename, e);
            process::exit(ERROR_CREATE_FILE_FAIL);  // Exit the program with a non-zero exit code to indicate an error
        }
    }
}

/// Reads the contents of a file as raw bytes into a vector.
fn read_file(filename: &str) -> Vec<u8> {
    let mut file = open_file(filename);
    let mut contents = Vec::new();

    if let Err(e) = file.read_to_end(&mut contents) {
        eprintln!("Error: Failed to read file {}: {}", filename, e);
        process::exit(ERROR_READ_FILE);  // Read error
    }

    contents
}