use encoding::label::encoding_from_whatwg_label;
use nom::{bytes::complete::take_till, IResult};
use std::str;

use super::parser::{record_block_parser, BlockEntryInfo, KeyBlock, KeyEntry};

pub struct Mdx {
    pub(crate) key_blocks: Vec<KeyBlock>,
    pub(crate) records_info: Vec<BlockEntryInfo>,
    pub(crate) records: Vec<u8>,
    pub encoding: String,
    pub encrypted: u8,
}

#[derive(Debug)]
struct RecordOffset {
    buf_offset: usize,
    block_offset: usize,
    record_size: usize,
    decomp_size: usize
}

#[derive(Debug)]
pub struct Record<'a> {
    pub key: &'a str,
    pub definition: String,
}

impl Mdx {
    pub fn items(&self) -> impl Iterator<Item = Record> {
        self.key_blocks
            .iter()
            .flat_map(|block| &block.entries)
            .map(|entry| {
                let def = self.find_definition(entry);
                Record {
                    key: &entry.text,
                    definition: def,
                }
                // (entry.text.as_str(), def)
            })
    }

    pub fn keys(&self) -> impl Iterator<Item = &KeyEntry> {
        self.key_blocks.iter().flat_map(|block| &block.entries)
    }

    fn record_offset(&self, entry: &KeyEntry) -> Option<RecordOffset> {
        let mut block_offset = 0;
        let mut buf_offset = 0;
        for i in &self.records_info {
            if entry.offset <= block_offset + i.decompressed_size {
                // return Some((item_offset, block_offset, i));
                return Some(RecordOffset {
                    buf_offset,
                    block_offset: entry.offset - block_offset,
                    record_size: i.compressed_size,
                    decomp_size: i.decompressed_size
                });
            } else {
                block_offset += i.decompressed_size;
                buf_offset += i.compressed_size;
            }
        }
        None
    }

    fn find_definition(&self, entry: &KeyEntry) -> String {
        if let Some(offset) = self.record_offset(entry) {
            let buf = &self.records[offset.buf_offset..];
            let (_, decompressed) = record_block_parser(offset.record_size, offset.decomp_size)(buf).unwrap();
            let result: IResult<&[u8], &[u8]> =
                take_till(|x| x == 0)(&decompressed[offset.block_offset..]);
            let (_, buf) = result.unwrap();
            let decoder = encoding_from_whatwg_label(self.encoding.as_str()).unwrap();
            let text = decoder.decode(buf,encoding::DecoderTrap::Strict).unwrap();
            text
        } else {
            "".to_string()
        }
    }
}
