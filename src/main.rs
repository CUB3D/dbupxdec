//! Decryptor and Decompressor for Dirty Bomb UPX files

use aes::Aes256;
use aes::cipher::BlockDecrypt;
use aes::cipher::KeyInit;
use aes::cipher::generic_array::GenericArray;
use clap::Parser;
use parse::{le_i32, le_u32, take, take_arr, take_vec};
use rust_lzo::{LZOContext, LZOError};
use std::path::PathBuf;

#[derive(Debug)]
pub struct FCompChunk {
    pub uncom_of: u32,
    pub uncom_sz: u32,
    pub comp_sz: u32,
    pub comp_off: u32,
}

#[derive(Debug)]
pub struct UpxFile {
    pub compflag: u32,
    pub chunks: Vec<FCompChunk>,
    pub compflag_off: usize,
    pub num_chunks_off: usize,
    pub table_off: usize,
}

#[derive(Debug)]
pub struct Fgen {
    pub expcnt: u32,
    pub namecnt: u32,
    pub netobjcnt: u32,
}

fn fgen(i: &[u8]) -> anyhow::Result<(&[u8], Fgen)> {
    let (i, expcnt) = le_u32(i)?;
    let (i, namecnt) = le_u32(i)?;
    let (i, netobjcnt) = le_u32(i)?;
    Ok((
        i,
        Fgen {
            expcnt,
            namecnt,
            netobjcnt,
        },
    ))
}

fn fstring(i: &[u8]) -> anyhow::Result<(&[u8], String)> {
    let (i, len) = le_i32(i)?;
    assert!(len >= 0); // ascii, null term
    let (i, s) = take(i, len as usize)?;
    Ok((
        i,
        String::from_utf8_lossy(s)
            .trim_end_matches('\0')
            .to_string(),
    ))
}

fn fcompchunk(i: &[u8]) -> anyhow::Result<(&[u8], FCompChunk)> {
    let (i, uncom_of) = le_u32(i)?;
    let (i, uncom_sz) = le_u32(i)?;
    let (i, comp_off) = le_u32(i)?;
    let (i, comp_sz) = le_u32(i)?;
    Ok((
        i,
        FCompChunk {
            uncom_of,
            uncom_sz,
            comp_sz,
            comp_off,
        },
    ))
}

fn parse_header(f: &[u8]) -> anyhow::Result<UpxFile> {
    let (i, sig) = le_u32(f)?;
    assert_eq!(
        sig, 0x9E2A83C1,
        "This doesn't look like a UPX file, wrong magic"
    );
    let (i, _ver) = le_u32(i)?;
    let (i, _hdrsz) = le_u32(i)?;

    let (i, _pkg) = fstring(i)?;

    let (i, _pkgflag) = le_u32(i)?;
    let (i, _name_count) = le_u32(i)?;
    let (i, _name_offset) = le_u32(i)?;
    let (i, _export_count) = le_u32(i)?;
    let (i, _export_offset) = le_u32(i)?;
    let (i, _import_count) = le_u32(i)?;
    let (i, _import_offset) = le_u32(i)?;
    let (i, _depoff) = le_u32(i)?;
    let (i, _seroff) = le_u32(i)?;
    let (i, _unk2) = le_u32(i)?;
    let (i, _unk3) = le_u32(i)?;
    let (i, _unk4) = le_u32(i)?;
    let (i, _guid) = take_arr::<16>(i)?;

    let (i, num_gens) = le_u32(i)?;
    let (i, _gens) = take_vec(i, num_gens as _, fgen)?;

    let (i, _enginever) = le_u32(i)?;
    let (i, _cookver) = le_u32(i)?;
    let compflag_off = i.as_ptr() as usize - f.as_ptr() as usize;
    let (i, compflag) = le_u32(i)?;
    assert_eq!(
        compflag & 0xF,
        2,
        "Only LZO (2) and DirtyBomb Encrypted LZO (202) are supported, got {compflag}"
    );
    let num_chunks_off = i.as_ptr() as usize - f.as_ptr() as usize;
    let (i, num_chunks) = le_u32(i)?;
    let table_off = i.as_ptr() as usize - f.as_ptr() as usize;
    let (_i, chunks) = take_vec(i, num_chunks as _, fcompchunk)?;

    Ok(UpxFile {
        compflag,
        chunks,
        compflag_off,
        num_chunks_off,
        table_off,
    })
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// The source file to read
    pub in_path: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let dat = std::fs::read(&args.in_path)?;
    let hdr = parse_header(&dat[..])?;

    let start = hdr.chunks.iter().map(|c| c.uncom_of).min().unwrap_or(0) as usize;
    let total = hdr
        .chunks
        .iter()
        .map(|c| c.uncom_of as u64 + c.uncom_sz as u64)
        .max()
        .unwrap_or(0) as usize;

    let mut content = vec![0u8; total];
    content[..start].copy_from_slice(&dat[..start]);

    let aes = Aes256::new_from_slice(b"sdjJKLJsklaJSLKJDWLZMXNsldjKjalk").unwrap();

    for c in &hdr.chunks {
        let base = c.comp_off as usize;

        let (i, _tag) = le_u32(&dat[base..])?;
        let (i, blk_sz) = le_u32(i)?;
        let (i, _total_comp) = le_u32(i)?;
        let (i, uncomp_sz) = le_u32(i)?;

        let blk_cnt = uncomp_sz.div_ceil(blk_sz);

        let mut doff = base + 16 + blk_cnt as usize * 8;
        let mut cur = c.uncom_of as usize;
        let mut i = i;
        for _bid in 0..blk_cnt {
            let (j, comp_sz) = le_u32(i)?;
            let (j, uncomp_sz) = le_u32(j)?;
            i = j;

            let (dec, err) = LZOContext::decompress_to_slice(
                &dat[doff..][..comp_sz as usize],
                &mut content[cur..][..uncomp_sz as usize],
            );
            if err != LZOError::OK {
                panic!("failed to decompress upx");
            }
            assert_eq!(dec.len(), uncomp_sz as usize);

            doff += comp_sz as usize;
            cur += uncomp_sz as usize;
        }

        if hdr.compflag & 0x200 != 0 {
            for blk in &mut content[c.uncom_of as usize..][..(c.uncom_sz & !0xF) as usize]
                .chunks_exact_mut(16)
            {
                aes.decrypt_block(GenericArray::from_mut_slice(blk));
            }
        }
    }

    // Remove compression flags and chunk table to mark as uncompressed
    content[hdr.compflag_off..][..4].fill(0);
    content[hdr.num_chunks_off..][..4].fill(0);
    let table_end = (hdr.table_off + hdr.chunks.len() * 16).min(start);
    content[hdr.table_off..table_end].fill(0);

    std::fs::write(args.in_path.with_extension("dec.u"), &content)?;

    Ok(())
}
