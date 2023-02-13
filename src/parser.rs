use std::{
    collections::HashMap,
    io::{self, Read},
    str,
};

use adler32::adler32;

use compress::zlib;
use encoding::{all::UTF_16LE, label::encoding_from_whatwg_label, Encoding};
use nom::{
    bytes::complete::{take, take_till},
    combinator::map,
    multi::{count, length_data, many0},
    number::complete::{be_u16, be_u32, be_u64, be_u8, le_u32},
    sequence::tuple,
    IResult, Slice,
};
use regex::Regex;
use ripemd::{Digest, Ripemd128};
use salsa20::{cipher::KeyIvInit, Salsa20};

use crate::mdict::Mdx;

#[derive(Debug)]
pub(crate) struct KeyBlock {
    pub(crate) entries: Vec<KeyEntry>,
}

#[derive(Debug)]
pub struct KeyEntry {
    pub offset: usize,
    pub text: String,
}

#[derive(Debug)]
pub struct Header {
    version: Version,
    encrypted: u8,
    encoding: String,
}

#[derive(Debug)]
struct KeyBlockHeader {
    block_num: usize,
    entry_num: usize,
    decompressed_size: usize,
    block_info_size: usize,
    key_block_size: usize,
}

#[derive(Debug)]
pub(crate) struct BlockEntryInfo {
    pub(crate) compressed_size: usize,
    pub(crate) decompressed_size: usize,
}

#[derive(Debug)]
enum Version {
    V1,
    V2,
    V3,
}

fn parse_header(input: &[u8]) -> IResult<&[u8], Header> {
    let (input, (info, chksum)) = tuple((length_data(be_u32), le_u32))(input)?;

    assert_eq!(adler32(info).unwrap(), chksum);

    let info = UTF_16LE
        .decode(info, encoding::DecoderTrap::Strict)
        .unwrap();
    let attrs = parse_key_value(info.as_str());

    let version = attrs
        .get("GeneratedByEngineVersion")
        .unwrap()
        .trim()
        .slice(0..1)
        .parse::<u8>()
        .unwrap();

    let version = match version {
        1 => Version::V1,
        2 => Version::V2,
        3 => Version::V3,
        _ => panic!("unsupported version"),
    };

    let encrypted = attrs
        .get("Encrypted")
        .and_then(|x| match x == "Yes" {
            true => Some(1_u8),
            false => x.as_str().parse().ok(),
        })
        .unwrap_or(0);

    let encoding = attrs
        .get("Encoding")
        .unwrap_or(&"UTF-8".to_string())
        .to_string();

    Ok((
        input,
        Header {
            version,
            encrypted,
            encoding,
        },
    ))
}

fn parse_key_value(s: &str) -> HashMap<String, String> {
    let re = Regex::new(r#"(\w+)="((.|\r\n|[\r\n])*?)""#).unwrap();
    let mut attrs = HashMap::new();
    for cap in re.captures_iter(s) {
        attrs.insert(cap[1].to_string(), cap[2].to_string());
    }
    attrs
}

fn parse_key_block_header_v2(input: &[u8]) -> IResult<&[u8], KeyBlockHeader> {
    let (input, block_info_buf) = take(40_usize)(input)?;
    let (input, chksum) = be_u32(input)?;
    assert_eq!(adler32(block_info_buf).unwrap(), chksum);

    let (_, res) = map(
        tuple((be_u64, be_u64, be_u64, be_u64, be_u64)),
        |(block_num, entry_num, decompressed_size, block_info_size, key_block_size)| {
            KeyBlockHeader {
                block_num: block_num as usize,
                entry_num: entry_num as usize,
                decompressed_size: decompressed_size as usize,
                block_info_size: block_info_size as usize,
                key_block_size: key_block_size as usize,
            }
        },
    )(block_info_buf)?;
    Ok((input, res))
}

fn parse_key_block_header_v1(input: &[u8]) -> IResult<&[u8], KeyBlockHeader> {
    let (input, block_info_buf) = take(16_usize)(input)?;

    let (_, res) = map(
        tuple((be_u32, be_u32, be_u32, be_u32)),
        |(block_num, entry_num, block_info_size, key_block_size)| KeyBlockHeader {
            block_num: block_num as usize,
            entry_num: entry_num as usize,
            decompressed_size: block_info_size as usize,
            block_info_size: block_info_size as usize,
            key_block_size: key_block_size as usize,
        },
    )(block_info_buf)?;
    Ok((input, res))
}

fn parse_key_block_header<'a>(
    input: &'a [u8],
    header: &'a Header,
) -> IResult<&'a [u8], KeyBlockHeader> {
    match header.version {
        Version::V2 => parse_key_block_header_v2(input),
        Version::V1 => parse_key_block_header_v1(input),
        _ => panic!("unsupported version"),
    }
}

fn parse_key_block_infos<'a>(
    input: &'a [u8],
    size: usize,
    dict_header: &'a Header,
) -> IResult<&'a [u8], Vec<BlockEntryInfo>> {
    match &dict_header.version {
        Version::V1 => parse_key_block_infos_v1(input, size),
        Version::V2 => parse_key_block_infos_v2(input, size, dict_header),
        _ => panic!("unsupported version"),
    }
}

fn parse_key_block_infos_v1<'a>(
    input: &'a [u8],
    size: usize,
) -> IResult<&'a [u8], Vec<BlockEntryInfo>> {
    let (input, block_info) = take(size)(input)?;
    let entry_infos = decode_key_block_info_v1(&block_info[..]);
    Ok((input, entry_infos))
}
fn parse_key_block_infos_v2<'a>(
    input: &'a [u8],
    size: usize,
    dict_header: &'a Header,
) -> IResult<&'a [u8], Vec<BlockEntryInfo>> {
    let (input, block_info) = take(size)(input)?;

    assert_eq!(block_info.slice(0..4), b"\x02\x00\x00\x00");
    let mut key_block_info = vec![];

    //decrypt
    if dict_header.encrypted == 2 {
        let mut md = Ripemd128::new();
        let mut v = Vec::from(block_info.slice(4..8));
        let value: u32 = 0x3695;
        v.extend_from_slice(&value.to_le_bytes());
        md.update(v);
        let key = md.finalize();
        let mut d = Vec::from(&block_info[0..8]);
        let decrypte = fast_decrypt(&block_info[8..], key.as_slice());
        d.extend(decrypte);
        zlib::Decoder::new(&d[8..])
            .read_to_end(&mut key_block_info)
            .unwrap();
    }

    let entry_infos = decode_key_block_info_v2(&key_block_info[..]);
    Ok((input, entry_infos))
}

fn text_len_parser_v2(input: &[u8]) -> IResult<&[u8], u16> {
    let (input, len) = be_u16(input)?;
    Ok((input, len + 1))
}

fn text_len_parser_v1(input: &[u8]) -> IResult<&[u8], u8> {
    be_u8(input)
}

fn decode_key_block_info_v1(input: &[u8]) -> Vec<BlockEntryInfo> {
    let mut info_parser = many0(map(
        tuple((
            be_u32,
            length_data(text_len_parser_v1),
            length_data(text_len_parser_v1),
            be_u32,
            be_u32,
        )),
        |(_, _, _, compressed_size, decompressed_size)| BlockEntryInfo {
            compressed_size: compressed_size as usize,
            decompressed_size: decompressed_size as usize,
        },
    ));
    let (remain, res) = info_parser(input).unwrap();
    assert_eq!(remain.len(), 0);
    res
}

fn decode_key_block_info_v2(input: &[u8]) -> Vec<BlockEntryInfo> {
    let mut info_parser = many0(map(
        tuple((
            be_u64,
            length_data(text_len_parser_v2),
            length_data(text_len_parser_v2),
            be_u64,
            be_u64,
        )),
        |(_, _, _, compressed_size, decompressed_size)| BlockEntryInfo {
            // num,
            compressed_size: compressed_size as usize,
            decompressed_size: decompressed_size as usize,
        },
    ));
    let (remain, res) = info_parser(input).unwrap();
    assert_eq!(remain.len(), 0);
    res
}

fn parse_key_blocks<'a>(
    input: &'a [u8],
    size: usize,
    header: &Header,
    block_infos: &'a Vec<BlockEntryInfo>,
) -> IResult<&'a [u8], Vec<KeyBlock>> {
    let (input, buf) = take(size)(input)?;

    let blocks = match &header.version {
        Version::V1 => decode_blocks(buf, block_infos, &header),
        Version::V2 => decode_blocks(buf, block_infos, &header),
        Version::V3 => panic!("unsupported version"),
    };

    Ok((input, blocks))
}

fn decode_blocks(buf: &[u8], entry_infos: &Vec<BlockEntryInfo>, header: &Header) -> Vec<KeyBlock> {
    let mut buf = buf;

    let mut res = vec![];
    for info in entry_infos.iter() {
        let (remain, decompressed) =
            block_parser(info.compressed_size, info.decompressed_size)(buf).unwrap();
        let (_, entries) = match &header.version {
            Version::V1 => parse_block_items_v1(&decompressed[..], &header.encoding).unwrap(),
            Version::V2 => parse_block_items_v2(&decompressed[..], &header.encoding).unwrap(),
            _ => panic!("unsupported version"),
        };

        buf = remain;
        res.push(KeyBlock { entries });
    }

    res
}

fn parse_block_items_v1<'a>(
    input: &'a [u8],
    encoding: &'a str,
) -> IResult<&'a [u8], Vec<KeyEntry>> {
    let (remain, sep) = many0(map(
        tuple((be_u32, take_till(|x| x == 0), take(1_usize))),
        |(offset, buf, _)| {
            let decoder = encoding_from_whatwg_label(encoding).unwrap();
            let text = decoder.decode(buf, encoding::DecoderTrap::Ignore).unwrap();
            KeyEntry {
                offset: offset as usize,
                text,
            }
        },
    ))(input)?;

    assert_eq!(remain.len(), 0);

    Ok((remain, sep))
}
fn parse_block_items_v2<'a>(
    input: &'a [u8],
    encoding: &'a str,
) -> IResult<&'a [u8], Vec<KeyEntry>> {
    let (remain, sep) = many0(map(
        tuple((be_u64, take_till(|x| x == 0), take(1_usize))),
        |(offset, buf, _)| {
            let decoder = encoding_from_whatwg_label(encoding).unwrap();
            let text = decoder.decode(buf, encoding::DecoderTrap::Ignore).unwrap();
            KeyEntry {
                offset: offset as usize,
                text,
            }
        },
    ))(input)?;

    assert_eq!(remain.len(), 0);

    Ok((remain, sep))
}

fn block_parser_v1<'a>(size: usize) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], Vec<u8>> {
    map(
        tuple((le_u32, take(4_usize), take(size - 8))),
        |(enc, chksum, encrypted)| {
            let enc_method = (enc >> 4) & 0xf;
            let enc_size = (enc >> 8) & 0xff;
            let comp_method = enc & 0xf;

            let mut md = Ripemd128::new();
            md.update(chksum);
            let key = md.finalize();

            let data: Vec<u8> = match enc_method {
                0 => Vec::from(encrypted),
                1 => fast_decrypt(encrypted, key.as_slice()),
                2 => {
                    let mut decrypt = vec![];
                    let mut cipher = Salsa20::new(key.as_slice().into(), &[0; 8].into());

                    decrypt
                }
                _ => panic!("unknown enc method: {}", enc_method),
            };

            let decompressed = match comp_method {
                0 => data,
                2 => {
                    let mut v = vec![];
                    zlib::Decoder::new(&data[..]).read_to_end(&mut v).unwrap();
                    v
                }
                _ => panic!("unknown compression method: {}", comp_method),
            };

            decompressed
        },
    )
}
fn block_parser<'a>(
    comp_size: usize,
    decomp_size: usize,
) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], Vec<u8>> {
    map(
        tuple((le_u32, take(4_usize), take(comp_size - 8))),
        move |(enc, chksum, encrypted)| {
            let enc_method = (enc >> 4) & 0xf;
            let enc_size = (enc >> 8) & 0xff;
            let comp_method = enc & 0xf;

            let mut md = Ripemd128::new();
            md.update(chksum);
            let key = md.finalize();

            let data: Vec<u8> = match enc_method {
                0 => Vec::from(encrypted),
                1 => fast_decrypt(encrypted, key.as_slice()),
                2 => {
                    let mut decrypt = vec![];
                    let mut cipher = Salsa20::new(key.as_slice().into(), &[0; 8].into());

                    decrypt
                }
                _ => panic!("unknown enc method: {}", enc_method),
            };

            let decompressed = match comp_method {
                0 => data,
                1 => {
                    let mut comp: Vec<u8> = vec![0xf0];
                    comp.extend_from_slice(&data[..]);
                    let lzo = minilzo_rs::LZO::init().unwrap();
                    lzo.decompress(&data[..], decomp_size).unwrap()
                }
                2 => {
                    let mut v = vec![];
                    zlib::Decoder::new(&data[..]).read_to_end(&mut v).unwrap();
                    v
                }
                _ => panic!("unknown compression method: {}", comp_method),
            };

            decompressed
        },
    )
}

fn parse_record_blocks<'a>(input: &'a [u8], header: &'a Header) -> IResult<&'a [u8], Vec<BlockEntryInfo>> {
    match &header.version {
        Version::V1 => parse_record_blocks_v1(input),
        Version::V2 => parse_record_blocks_v2(input),
        _ => panic!("unsupported version"),
    }
}

fn parse_record_blocks_v1(input: &[u8]) -> IResult<&[u8], Vec<BlockEntryInfo>> {
    let (input, records) = be_u32(input)?;
    let (input, entries) = be_u32(input)?;
    let (input, record_info_size) = be_u32(input)?;
    let (input, record_buf_size) = be_u32(input)?;

    assert_eq!(records * 8, record_info_size);

    count(
        map(
            tuple((be_u32, be_u32)),
            |(compressed_size, decompressed_size)| BlockEntryInfo {
                compressed_size: compressed_size as usize,
                decompressed_size: decompressed_size as usize,
            },
        ),
        records as usize,
    )(input)
}
fn parse_record_blocks_v2(input: &[u8]) -> IResult<&[u8], Vec<BlockEntryInfo>> {
    let (input, records) = be_u64(input)?;
    let (input, entries) = be_u64(input)?;
    let (input, record_info_size) = be_u64(input)?;
    let (input, record_buf_size) = be_u64(input)?;

    assert_eq!(records * 16, record_info_size);

    count(
        map(
            tuple((be_u64, be_u64)),
            |(compressed_size, decompressed_size)| BlockEntryInfo {
                compressed_size: compressed_size as usize,
                decompressed_size: decompressed_size as usize,
            },
        ),
        records as usize,
    )(input)
}

fn fast_decrypt(encrypted: &[u8], key: &[u8]) -> Vec<u8> {
    let mut buf = Vec::from(encrypted);
    let mut prev = 0x36;
    for i in 0..buf.len() {
        let mut t = buf[i] >> 4 | buf[i] << 4;
        t = t ^ prev ^ (i as u8) ^ key[i % key.len()];
        prev = buf[i];
        buf[i] = t;
    }
    buf
}

pub(crate) fn record_block_parser<'a>(
    size: usize,
    decomp_size:usize
) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], Vec<u8>> {
    map(
        tuple((le_u32, take(4_usize), take(size - 8))),
        move |(enc, chksum, encrypted)| {
            let enc_method = (enc >> 4) & 0xf;
            let enc_size = (enc >> 8) & 0xff;
            let comp_method = enc & 0xf;

            let mut md = Ripemd128::new();
            md.update(chksum);
            let key = md.finalize();

            let data: Vec<u8> = match enc_method {
                0 => Vec::from(encrypted),
                1 => fast_decrypt(encrypted, key.as_slice()),
                2 => {
                    let mut decrypt = vec![];
                    let mut cipher = Salsa20::new(key.as_slice().into(), &[0; 8].into());

                    decrypt
                }
                _ => panic!("unknown enc method: {}", enc_method),
            };

            let decompressed = match comp_method {
                0 => data,
                1 => {
                    let lzo = minilzo_rs::LZO::init().unwrap();
                    lzo.decompress(&data[..], decomp_size).unwrap()
                },
                2 => {
                    let mut v = vec![];
                    zlib::Decoder::new(&data[..]).read_to_end(&mut v).unwrap();
                    v
                }
                _ => panic!("unknown compression method: {}", comp_method),
            };

            decompressed
        },
    )
}

pub fn parse(data: &[u8]) -> Mdx {
    let (input, header) = parse_header(data).unwrap();
    let (input, key_block_header) = parse_key_block_header(input, &header).unwrap();
    let (input, key_block_infos) =
        parse_key_block_infos(input, key_block_header.block_info_size, &header).unwrap();
    let (input, key_blocks) = parse_key_blocks(
        input,
        key_block_header.key_block_size,
        &header,
        &key_block_infos,
    )
    .unwrap();
    let (input, record_blocks) = parse_record_blocks(input, &header).unwrap();
    Mdx {
        key_blocks,
        records_info: record_blocks,
        records: Vec::from(input),
        encoding: header.encoding,
        encrypted: header.encrypted,
    }
}
