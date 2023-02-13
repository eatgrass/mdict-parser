use mdict_parser::{parser, mdict::Record};

#[test]
fn test_opted003() {
    let input = include_bytes!("../tests/opted003.mdx");
    let dict = parser::parse(input);
    println!("{:?}", dict.items().take(10).collect::<Vec<Record>>());
}

#[test]
fn test_etdict() {
    let input = include_bytes!("../tests/ETDict.mdx");
    let dict = parser::parse(input);
    println!("{:?}", dict.items().take(10).collect::<Vec<Record>>());
}


#[test]
fn test_wordnet20() {
    let input = include_bytes!("../tests/wordnet20.mdx");
    let dict = parser::parse(input);
    println!("{:?}", dict.items().take(10).collect::<Vec<Record>>());
}
