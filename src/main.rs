
extern crate clap;

use clap::{Arg, App, ArgMatches};
use std::fs::File;
use std::io::{Read, Write, Error};

const PLAIN_PARAM:  &'static str = "plaintext";
const CIPHER_PARAM: &'static str = "ciphertext";
const KEY_PARAM:    &'static str = "keyfile";
const OUT_PARAM:    &'static str = "output";

enum CryptOp<'a> {
    Encrypt(&'a str),
    Decrypt(&'a str),
}

fn parse_arg<'a>() -> ArgMatches<'a> {
    App::new("Substitution Cipher Rust")
        .version("0.1.0")
        .author("Henning Ottesen <henning@live.no>")
        .about("Very simple encrypt decrypt utility for polyalphabetic substitution ciphers.")
        .arg(Arg::with_name(PLAIN_PARAM)
            .short("p")
            .long("plaintext")
            .value_name("FILE")
            .help("Plaintext file")
            .conflicts_with(CIPHER_PARAM)
            .required_unless(CIPHER_PARAM)
            .takes_value(true))
        .arg(Arg::with_name(CIPHER_PARAM)
            .short("c")
            .long("ciphertext")
            .value_name("FILE")
            .help("Ciphertext file")
            .conflicts_with(PLAIN_PARAM)
            .required_unless(PLAIN_PARAM)
            .takes_value(true))
        .arg(Arg::with_name(KEY_PARAM)
            .short("k")
            .long("keyfile")
            .value_name("FILE")
            .help("Keyfile file")
            .required(true)
            .takes_value(true))
        .arg(Arg::with_name(OUT_PARAM)
            .short("o")
            .long("out")
            .value_name("FILE")
            .help("Output file")
            .required(true)
            .takes_value(true))
        .get_matches()
}

fn crypt<'a, F>(input: &'a str, output: &'a str, key: &'a str, mut f: F) -> Result<(), (Error, &'a str)> where F: FnMut(&mut u8, &u8) {
    let mut input_file  = File::open(input).map_err(|e| (e, input))?;
    let mut key_file    = File::open(key).map_err(|e| (e, key))?;
    let mut output_file = File::create(output).map_err(|e| (e, output))?;

    let mut key_buf  = Vec::new();
    let mut data_buf = Vec::new();

    key_file.read_to_end(&mut key_buf).map_err(|e| (e, key))?;
    input_file.read_to_end(&mut data_buf).map_err(|e| (e, input))?;

    for r in data_buf.iter_mut().zip(key_buf.iter().cycle()) {
        f(r.0, r.1);
    }

    output_file.write_all(&mut data_buf).map_err(|e| (e, output))?;

    Ok(())
}

fn main() {
    let args = parse_arg();

    let key_file = args.value_of(KEY_PARAM).unwrap();
    let out_file = args.value_of(OUT_PARAM).unwrap();

     match args.value_of(PLAIN_PARAM).map(|fname| CryptOp::Encrypt(fname)).unwrap_or_else(|| {
         args.value_of(CIPHER_PARAM).map(|fname| CryptOp::Decrypt(fname)).unwrap()
    }){
        CryptOp::Encrypt(fname) => {
            crypt(fname, out_file, key_file, |p, k| {
                *p = (*p).wrapping_add(*k);  
            })
        },
        CryptOp::Decrypt(fname) => {
            crypt(fname, out_file, key_file, |c, k| {
                *c = (*c).wrapping_sub(*k);
            })
        },
    }.map_err(|e| format!("File I/O error on file \"{}\", Error Message \"{}\"", e.1, e.0)).unwrap();
}
