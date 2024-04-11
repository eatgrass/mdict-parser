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
use mdict_parser::{parser, mdict::Record};

fn main() {
    let input = include_bytes!("../dictionary.mdx");
    let dict = parser::parse(input);

    // iter dictionary entries
    for key in dict.keys() {
      println!("{:?}", key);
    }

    // iter all dictionary records
    for item in dict.items() {
      println!("{:?}", item);
    }
}
```
## Unimplemented Features

* `.mdd` file format support
* mdict v3 format support
* Encrypted dictionary file support

## License

mdict-parser is licensed under the MIT License.





