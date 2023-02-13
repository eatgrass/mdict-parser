# mdict-parser

A Rust project for parsing mdict dictionaries.

## Introduction

mdict-parser is a tool for parsing mdict dictionaries, a commonly used file format for dictionaries. The resulting output is in a format that can be easily used for other purposes, such as building a dictionary or integrating with other applications.

## Features

Parses mdict dictionary `.mdx` files into a structured format
Supports multi-value entries
Written in Rust for performance and safety

## Usage

Add the following to your Cargo.toml file:

```toml
[dependencies]
mdict-parser = "0.1.0"
```

Add the following to your Cargo.toml file:


```rust
use mdict_parser::parser;

fn main() {
    let mdict = Mdict::from_file("example.mdx").unwrap();
    for entry in mdict.entries() {
        println!("{}: {}", entry.key, entry.value);
    }
}
```
## Unimplemented Features

* `.mdd` file format support
* UTF-16 encoding support
* mdict v3 format support
* Encrypted dictionary file support

## License

mdict-parser is licensed under the MIT License.





