use std::collections::HashMap;
use std::env;
use std::ffi::c_void;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::process;
use std::time::Instant;

#[link(name = "kernel32")]
extern "system" {
    fn CreateFileW(
        lpFileName: *const u16,
        dwDesiredAccess: u32,
        dwShareMode: u32,
        lpSecurityAttributes: *const c_void,
        dwCreationDisposition: u32,
        dwFlagsAndAttributes: u32,
        hTemplateFile: *mut c_void,
    ) -> *mut c_void;
    fn DeviceIoControl(
        hDevice: *mut c_void,
        dwIoControlCode: u32,
        lpInBuffer: *const c_void,
        nInBufferSize: u32,
        lpOutBuffer: *mut c_void,
        nOutBufferSize: u32,
        lpBytesReturned: *mut u32,
        lpOverlapped: *mut c_void,
    ) -> i32;
    fn ReadFile(
        hFile: *mut c_void,
        lpBuffer: *mut u8,
        nNumberOfBytesToRead: u32,
        lpNumberOfBytesRead: *mut u32,
        lpOverlapped: *mut c_void,
    ) -> i32;
    fn SetFilePointerEx(
        hFile: *mut c_void,
        liDistanceToMove: i64,
        lpNewFilePointer: *mut i64,
        dwMoveMethod: u32,
    ) -> i32;
    fn CloseHandle(hObject: *mut c_void) -> i32;
    fn GetLastError() -> u32;
}

const INVALID_HANDLE_VALUE: *mut c_void = -1isize as *mut c_void;
const GENERIC_READ: u32 = 0x8000_0000;
const FILE_SHARE_ALL: u32 = 0x0000_0007;
const OPEN_EXISTING: u32 = 3;
const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;
const FSCTL_GET_NTFS_VOLUME_DATA: u32 = 0x0009_0064;
const FILE_BEGIN: u32 = 0;
const NCAT: usize = 11;

#[inline]
fn r_u16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
#[inline]
fn r_u32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
#[inline]
fn r_u64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes([
        b[o], b[o + 1], b[o + 2], b[o + 3], b[o + 4], b[o + 5], b[o + 6], b[o + 7],
    ])
}
#[inline]
fn r_i64(b: &[u8], o: usize) -> i64 {
    i64::from_le_bytes([
        b[o], b[o + 1], b[o + 2], b[o + 3], b[o + 4], b[o + 5], b[o + 6], b[o + 7],
    ])
}

#[inline]
fn filetime_to_unix(ft: u64) -> f64 {
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
    if ft > EPOCH_DIFF {
        (ft - EPOCH_DIFF) as f64 / 10_000_000.0
    } else {
        0.0
    }
}

fn cat_of(name: &str) -> usize {
    let dot = match name.rfind('.') {
        Some(i) if i + 1 < name.len() => &name[i + 1..],
        _ => return NCAT - 1,
    };
    if dot.len() > 12 || !dot.is_ascii() {
        return NCAT - 1;
    }
    let mut buf = [0u8; 12];
    for (i, &c) in dot.as_bytes().iter().enumerate() {
        buf[i] = c.to_ascii_lowercase();
    }
    let ext = unsafe { std::str::from_utf8_unchecked(&buf[..dot.len()]) };
    match ext {
        "wav" | "aif" | "aiff" | "mp3" | "flac" | "ogg" | "m4a" | "wma" | "mid" | "midi" => 0,
        "nkx" | "nxs" | "ncw" | "nkc" | "nki" | "nkm" | "nks" | "nkr" | "stw" | "exs" | "sf2"
        | "sfz" => 1,
        "flp" | "als" | "logic" | "cpr" | "ptx" | "rpp" | "song" | "reapeaks" => 2,
        "mkv" | "mp4" | "avi" | "mov" | "wmv" | "webm" | "flv" | "m4v" => 3,
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "tga" | "tif" | "tiff" | "psd" | "webp"
        | "raw" | "dds" => 4,
        "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "txt" | "rtf" | "odt"
        | "md" | "epub" | "djvu" => 5,
        "zip" | "rar" | "7z" | "iso" | "gz" | "tar" | "bz2" | "img" | "cab" => 6,
        "exe" | "dll" | "msi" | "sys" | "lib" | "ocx" | "vst" | "vst3" | "bin" => 7,
        "big" | "pak" | "bsa" | "gm" | "an" | "tx" | "wad" | "pck" | "vpk" => 8,
        "blend" | "fbx" | "obj" | "max" | "3ds" | "ma" | "mb" | "stl" | "glb" | "gltf"
        | "unitypackage" => 9,
        _ => 10,
    }
}

struct HandleGuard(*mut c_void);
impl Drop for HandleGuard {
    fn drop(&mut self) {
        if self.0 != INVALID_HANDLE_VALUE && !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

fn read_at(h: *mut c_void, offset: u64, buf: &mut [u8]) -> Result<usize, u32> {
    let mut new_pos: i64 = 0;
    let ok = unsafe { SetFilePointerEx(h, offset as i64, &mut new_pos, FILE_BEGIN) };
    if ok == 0 {
        return Err(unsafe { GetLastError() });
    }
    let mut total = 0usize;
    while total < buf.len() {
        let to_read = (buf.len() - total).min(u32::MAX as usize) as u32;
        let mut got: u32 = 0;
        let ok = unsafe {
            ReadFile(
                h,
                buf[total..].as_mut_ptr(),
                to_read,
                &mut got,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(unsafe { GetLastError() });
        }
        if got == 0 {
            break;
        }
        total += got as usize;
    }
    Ok(total)
}

fn apply_usa(rec: &mut [u8], bps: usize) -> bool {
    if rec.len() < 48 || &rec[0..4] != b"FILE" {
        return false;
    }
    let usa_off = r_u16(rec, 4) as usize;
    let usa_cnt = r_u16(rec, 6) as usize;
    if usa_cnt < 2 || usa_off + usa_cnt * 2 > rec.len() || bps < 2 {
        return true;
    }
    for i in 1..usa_cnt {
        let sec_end = i * bps;
        if sec_end > rec.len() {
            break;
        }
        let f0 = rec[usa_off + i * 2];
        let f1 = rec[usa_off + i * 2 + 1];
        rec[sec_end - 2] = f0;
        rec[sec_end - 1] = f1;
    }
    true
}

fn parse_runlist(data: &[u8]) -> Vec<(u64, u64)> {
    let mut runs = Vec::new();
    let mut pos = 0usize;
    let mut cur_lcn: i64 = 0;
    while pos < data.len() {
        let hdr = data[pos];
        pos += 1;
        if hdr == 0 {
            break;
        }
        let len_sz = (hdr & 0x0F) as usize;
        let off_sz = (hdr >> 4) as usize;
        if len_sz == 0 || len_sz > 8 || off_sz > 8 || pos + len_sz + off_sz > data.len() {
            break;
        }
        let mut cnt: u64 = 0;
        for i in 0..len_sz {
            cnt |= (data[pos + i] as u64) << (i * 8);
        }
        pos += len_sz;
        if off_sz > 0 {
            let mut raw: u64 = 0;
            for i in 0..off_sz {
                raw |= (data[pos + i] as u64) << (i * 8);
            }
            if (data[pos + off_sz - 1] & 0x80) != 0 && off_sz < 8 {
                raw |= !0u64 << (off_sz * 8);
            }
            let delta = raw as i64;
            pos += off_sz;
            cur_lcn += delta;
            if cur_lcn >= 0 && cnt > 0 {
                runs.push((cur_lcn as u64, cnt));
            }
        }
    }
    runs
}

fn read_record(
    h: *mut c_void,
    runs: &[(u64, u64)],
    bpc: u64,
    rec_idx: u64,
    bpr: usize,
    bps: usize,
) -> Option<Vec<u8>> {
    let target = rec_idx * bpr as u64;
    let mut voff: u64 = 0;
    for &(lcn, cnt) in runs {
        let ext_len = cnt * bpc;
        if target < voff + ext_len {
            let disk_off = lcn * bpc + (target - voff);
            let mut buf = vec![0u8; bpr];
            if read_at(h, disk_off, &mut buf).ok()? == bpr && apply_usa(&mut buf, bps) {
                return Some(buf);
            }
            return None;
        }
        voff += ext_len;
    }
    None
}

fn extract_mft_runs(
    h: *mut c_void,
    mft_start_lcn: u64,
    bpc: u64,
    bpr: usize,
    bps: usize,
) -> Option<Vec<(u64, u64)>> {
    let mut rec0 = vec![0u8; bpr];
    if read_at(h, mft_start_lcn * bpc, &mut rec0).ok()? != bpr {
        return None;
    }
    if !apply_usa(&mut rec0, bps) {
        return None;
    }

    let mut runs_by_vcn: Vec<(u64, Vec<(u64, u64)>)> = Vec::new();
    let mut attr_list_recs: Vec<u64> = Vec::new();

    let mut off = r_u16(&rec0, 20) as usize;
    while off + 16 <= bpr {
        let atype = r_u32(&rec0, off);
        if atype == 0xFFFF_FFFF {
            break;
        }
        let alen = r_u32(&rec0, off + 4) as usize;
        if alen < 16 || off + alen > bpr {
            break;
        }
        let non_res = rec0[off + 8];
        let nlen = rec0[off + 9];
        if atype == 0x80 && nlen == 0 && non_res != 0 && off + 64 <= off + alen {
            let start_vcn = r_u64(&rec0, off + 16);
            let mp_off = off + r_u16(&rec0, off + 32) as usize;
            if mp_off < off + alen {
                runs_by_vcn.push((start_vcn, parse_runlist(&rec0[mp_off..off + alen])));
            }
        } else if atype == 0x20 && non_res == 0 && off + 24 <= off + alen {
            let v_len = r_u32(&rec0, off + 16) as usize;
            let v_off = off + r_u16(&rec0, off + 20) as usize;
            if v_off + v_len <= off + alen {
                let al = &rec0[v_off..v_off + v_len];
                let mut p = 0usize;
                while p + 26 <= al.len() {
                    let etype = r_u32(al, p);
                    let elen = r_u16(al, p + 4) as usize;
                    if elen < 26 || p + elen > al.len() {
                        break;
                    }
                    let enamelen = al[p + 6];
                    if etype == 0x80 && enamelen == 0 {
                        let ref_id = r_u64(al, p + 16) & 0x0000_FFFF_FFFF_FFFF;
                        if ref_id != 0 && !attr_list_recs.contains(&ref_id) {
                            attr_list_recs.push(ref_id);
                        }
                    }
                    p += elen;
                }
            }
        }
        off += alen;
    }

    if !attr_list_recs.is_empty() && !runs_by_vcn.is_empty() {
        let base_runs = runs_by_vcn[0].1.clone();
        for ext_idx in attr_list_recs {
            if let Some(ext_rec) = read_record(h, &base_runs, bpc, ext_idx, bpr, bps) {
                let mut o = r_u16(&ext_rec, 20) as usize;
                while o + 16 <= bpr {
                    let atype = r_u32(&ext_rec, o);
                    if atype == 0xFFFF_FFFF {
                        break;
                    }
                    let alen = r_u32(&ext_rec, o + 4) as usize;
                    if alen < 16 || o + alen > bpr {
                        break;
                    }
                    let non_res = ext_rec[o + 8];
                    let nlen = ext_rec[o + 9];
                    if atype == 0x80 && nlen == 0 && non_res != 0 && o + 64 <= o + alen {
                        let start_vcn = r_u64(&ext_rec, o + 16);
                        let mp_off = o + r_u16(&ext_rec, o + 32) as usize;
                        if mp_off < o + alen {
                            runs_by_vcn.push((start_vcn, parse_runlist(&ext_rec[mp_off..o + alen])));
                        }
                    }
                    o += alen;
                }
            }
        }
    }

    if runs_by_vcn.is_empty() {
        return None;
    }
    runs_by_vcn.sort_by_key(|x| x.0);
    let mut all_runs = Vec::new();
    for (_, r) in runs_by_vcn {
        all_runs.extend(r);
    }
    Some(all_runs)
}

#[derive(Default)]
struct RecInfo {
    valid: bool,
    is_dir: bool,
    is_reparse: bool,
    parent: u64,
    name: String,
    name_ns: u8,
    has_name: bool,
    ctime: f64,
    mtime: f64,
    atime: f64,
    size: u64,
    has_std_time: bool,
}

fn decode_utf16(bytes: &[u8]) -> String {
    let mut u16s = Vec::with_capacity(bytes.len() / 2);
    for ch in bytes.chunks_exact(2) {
        u16s.push(u16::from_le_bytes([ch[0], ch[1]]));
    }
    String::from_utf16_lossy(&u16s)
}

struct DirNode {
    name: String,
    ctime: f64,
    mt: f64,
    own_sz: u64,
    own_n: u64,
    own_cat: Option<[u64; NCAT]>,
    own_t1: f64,
    own_t2: f64,
    fl: Vec<(String, u64, f64, f64, f64)>,
    children: Vec<u32>,
}

fn write_json_str<W: Write>(w: &mut W, s: &str) -> std::io::Result<()> {
    w.write_all(b"\"")?;
    let mut last = 0usize;
    for (i, ch) in s.char_indices() {
        let esc = match ch {
            '"' => Some("\\\""),
            '\\' => Some("\\\\"),
            '\n' => Some("\\n"),
            '\r' => Some("\\r"),
            '\t' => Some("\\t"),
            c if (c as u32) < 0x20 => {
                if i > last {
                    w.write_all(&s.as_bytes()[last..i])?;
                }
                write!(w, "\\u{:04x}", c as u32)?;
                last = i + ch.len_utf8();
                continue;
            }
            _ => None,
        };
        if let Some(e) = esc {
            if i > last {
                w.write_all(&s.as_bytes()[last..i])?;
            }
            w.write_all(e.as_bytes())?;
            last = i + ch.len_utf8();
        }
    }
    if last < s.len() {
        w.write_all(&s.as_bytes()[last..])?;
    }
    w.write_all(b"\"")
}

fn dump_dir<W: Write>(
    w: &mut W,
    idx: u32,
    dirs: &[DirNode],
    root_name: Option<&str>,
) -> std::io::Result<()> {
    let d = &dirs[idx as usize];
    w.write_all(b"[")?;
    write_json_str(w, root_name.unwrap_or(&d.name))?;
    write!(w, ",{:.3},{:.3},0,[{},{},", d.ctime, d.mt, d.own_sz, d.own_n)?;
    match &d.own_cat {
        Some(cat) => {
            w.write_all(b"[")?;
            for (i, v) in cat.iter().enumerate() {
                if i > 0 {
                    w.write_all(b",")?;
                }
                write!(w, "{}", v)?;
            }
            w.write_all(b"]")?;
        }
        None => w.write_all(b"null")?,
    }
    write!(w, ",{:.3},{:.3}],[", d.own_t1, d.own_t2)?;
    for (i, (fname, fsz, fct, fmt, fat)) in d.fl.iter().enumerate() {
        if i > 0 {
            w.write_all(b",")?;
        }
        w.write_all(b"[")?;
        write_json_str(w, fname)?;
        write!(w, ",{},{:.3},{:.3},{:.3}]", fsz, fct, fmt, fat)?;
    }
    w.write_all(b"],[")?;
    for (i, &cidx) in d.children.iter().enumerate() {
        if i > 0 {
            w.write_all(b",")?;
        }
        dump_dir(w, cidx, dirs, None)?;
    }
    w.write_all(b"]]")
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!("USAGE: mft_scan <root_path> <keep_bytes> <out_json_path>");
        process::exit(1);
    }
    let root_path = &args[1];
    let keep_bytes: u64 = args[2].parse().unwrap_or(1 << 20);
    let out_json_path = &args[3];

    let drive_byte = root_path.as_bytes().first().copied().unwrap_or(0);
    if !drive_byte.is_ascii_alphabetic() {
        eprintln!("BAD_PATH");
        process::exit(1);
    }
    let vol_str = format!("\\\\.\\{}:", (drive_byte as char).to_ascii_uppercase());
    let mut vol_w: Vec<u16> = vol_str.encode_utf16().collect();
    vol_w.push(0);

    let h = unsafe {
        CreateFileW(
            vol_w.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_ALL,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_SEQUENTIAL_SCAN,
            std::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE || h.is_null() {
        let err = unsafe { GetLastError() };
        if err == 5 {
            eprintln!("ACCESS_DENIED");
        } else {
            eprintln!("OPEN_ERR_{}", err);
        }
        process::exit(1);
    }
    let _guard = HandleGuard(h);

    let mut vol_data = [0u8; 96];
    let mut bytes_ret: u32 = 0;
    let ok = unsafe {
        DeviceIoControl(
            h,
            FSCTL_GET_NTFS_VOLUME_DATA,
            std::ptr::null(),
            0,
            vol_data.as_mut_ptr() as *mut c_void,
            vol_data.len() as u32,
            &mut bytes_ret,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 || bytes_ret < 72 {
        eprintln!("NOT_NTFS");
        process::exit(2);
    }

    let bps_raw = r_u32(&vol_data, 40) as usize;
    let bps = if bps_raw >= 512 { bps_raw } else { 512 };
    let bpc = r_u32(&vol_data, 44) as u64;
    let bpr = r_u32(&vol_data, 48) as usize;
    let mft_valid_len = r_i64(&vol_data, 56);
    let mft_start_lcn = r_i64(&vol_data, 64);
    if bpc == 0 || bpr < 512 || mft_start_lcn < 0 {
        eprintln!("BAD_NTFS_GEOM");
        process::exit(2);
    }

    let runs = match extract_mft_runs(h, mft_start_lcn as u64, bpc, bpr, bps) {
        Some(r) if !r.is_empty() => r,
        _ => {
            eprintln!("MFT_RUNS_ERR");
            process::exit(3);
        }
    };

    let runs_bytes: u64 = runs.iter().map(|&(_, c)| c * bpc).sum();
    let total_mft_bytes: u64 = if mft_valid_len > 0 {
        (mft_valid_len as u64).min(runs_bytes)
    } else {
        runs_bytes
    };
    let est_recs = (total_mft_bytes / bpr as u64) as usize;

    let mut recs: Vec<RecInfo> = Vec::with_capacity(est_recs + 64);
    let chunk_target: usize = 4 * 1024 * 1024;
    let align = (bpc as usize).max(bpr);
    let chunk_bytes = ((chunk_target / align).max(1)) * align;
    let mut buf = vec![0u8; chunk_bytes];

    let mut bytes_done: u64 = 0;
    let mut rec_idx: u64 = 0;
    let mut files_seen: u64 = 0;
    let mut bytes_seen: u64 = 0;
    let mut last_tick = Instant::now();

    'outer: for &(lcn, cnt) in &runs {
        if bytes_done >= total_mft_bytes {
            break;
        }
        let mut ext_off: u64 = 0;
        let ext_len = cnt * bpc;
        let base_disk_off = lcn * bpc;
        while ext_off < ext_len && bytes_done < total_mft_bytes {
            let rem_ext = ext_len - ext_off;
            let rem_mft = total_mft_bytes - bytes_done;
            let want = (rem_ext.min(rem_mft).min(chunk_bytes as u64)) as usize;
            let got = match read_at(h, base_disk_off + ext_off, &mut buf[..want]) {
                Ok(g) if g > 0 => g,
                Ok(_) => break 'outer,
                Err(e) => {
                    eprintln!("READ_ERR_{}", e);
                    process::exit(4);
                }
            };
            let full_recs = got / bpr;
            for r in 0..full_recs {
                let rec = &mut buf[r * bpr..(r + 1) * bpr];
                if &rec[0..4] == b"FILE" {
                    let flags = r_u16(rec, 22);
                    if (flags & 0x0001) != 0 && apply_usa(rec, bps) {
                        let base_ref = r_u64(rec, 32) & 0x0000_FFFF_FFFF_FFFF;
                        let target_idx = if base_ref != 0 {
                            base_ref as usize
                        } else {
                            rec_idx as usize
                        };
                        if target_idx >= recs.len() {
                            recs.resize_with(target_idx + 1, RecInfo::default);
                        }
                        let info = &mut recs[target_idx];
                        if base_ref == 0 {
                            info.valid = true;
                            info.is_dir = (flags & 0x0002) != 0;
                        }

                        let mut off = r_u16(rec, 20) as usize;
                        while off + 16 <= bpr {
                            let atype = r_u32(rec, off);
                            if atype == 0xFFFF_FFFF {
                                break;
                            }
                            let alen = r_u32(rec, off + 4) as usize;
                            if alen < 16 || off + alen > bpr {
                                break;
                            }
                            let non_res = rec[off + 8];
                            let nlen = rec[off + 9];

                            match atype {
                                0x10 if non_res == 0 && off + 24 <= off + alen => {
                                    let v_off = off + r_u16(rec, off + 20) as usize;
                                    if v_off + 36 <= off + alen {
                                        let ct = filetime_to_unix(r_u64(rec, v_off));
                                        let mt = filetime_to_unix(r_u64(rec, v_off + 8));
                                        let at = filetime_to_unix(r_u64(rec, v_off + 24));
                                        let dos = r_u32(rec, v_off + 32);
                                        info.ctime = ct;
                                        info.mtime = mt;
                                        info.atime = at;
                                        info.has_std_time = true;
                                        if (dos & 0x0400) != 0 {
                                            info.is_reparse = true;
                                        }
                                    }
                                }
                                0x30 if non_res == 0 && off + 24 <= off + alen => {
                                    let v_off = off + r_u16(rec, off + 20) as usize;
                                    if v_off + 66 <= off + alen {
                                        let fn_len = rec[v_off + 64] as usize;
                                        let fn_ns = rec[v_off + 65];
                                        let name_end = v_off + 66 + fn_len * 2;
                                        if fn_len > 0 && name_end <= off + alen {
                                            let take = !info.has_name
                                                || (info.name_ns == 2 && fn_ns != 2);
                                            if take {
                                                info.parent =
                                                    r_u64(rec, v_off) & 0x0000_FFFF_FFFF_FFFF;
                                                info.name =
                                                    decode_utf16(&rec[v_off + 66..name_end]);
                                                info.name_ns = fn_ns;
                                                info.has_name = true;
                                                if !info.has_std_time {
                                                    info.ctime =
                                                        filetime_to_unix(r_u64(rec, v_off + 8));
                                                    info.mtime =
                                                        filetime_to_unix(r_u64(rec, v_off + 16));
                                                    info.atime =
                                                        filetime_to_unix(r_u64(rec, v_off + 32));
                                                }
                                            }
                                            let fn_flags = r_u32(rec, v_off + 56);
                                            if (fn_flags & 0x0400) != 0 {
                                                info.is_reparse = true;
                                            }
                                        }
                                    }
                                }
                                0x80 if nlen == 0 && !info.is_dir => {
                                    if non_res == 0 && off + 20 <= off + alen {
                                        let sz = r_u32(rec, off + 16) as u64;
                                        info.size += sz;
                                        bytes_seen += sz;
                                    } else if non_res != 0 && off + 56 <= off + alen {
                                        let start_vcn = r_u64(rec, off + 16);
                                        if start_vcn == 0 {
                                            let sz = r_u64(rec, off + 48);
                                            info.size += sz;
                                            bytes_seen += sz;
                                        }
                                    }
                                }
                                0xC0 => {
                                    info.is_reparse = true;
                                }
                                _ => {}
                            }
                            off += alen;
                        }
                        if base_ref == 0 && !info.is_dir && rec_idx >= 24 {
                            files_seen += 1;
                        }
                    }
                }
                rec_idx += 1;
            }
            ext_off += got as u64;
            bytes_done += got as u64;

            if last_tick.elapsed().as_millis() >= 200 {
                let pct = if total_mft_bytes > 0 {
                    ((bytes_done * 100) / total_mft_bytes).min(99)
                } else {
                    0
                };
                println!("P {} {} {}", files_seen, bytes_seen, pct);
                let _ = std::io::stdout().flush();
                last_tick = Instant::now();
            }
        }
    }

    if recs.len() <= 5 || !recs[5].valid || !recs[5].is_dir {
        eprintln!("NO_ROOT_5");
        process::exit(5);
    }

    let mut dir_map: HashMap<u64, u32> = HashMap::new();
    let mut dirs: Vec<DirNode> = Vec::new();

    for (idx, r) in recs.iter().enumerate() {
        let idx64 = idx as u64;
        if !r.valid || !r.is_dir {
            continue;
        }
        if idx64 != 5 && (idx64 < 24 || r.is_reparse || !r.has_name || r.name.is_empty()) {
            continue;
        }
        let d_id = dirs.len() as u32;
        dir_map.insert(idx64, d_id);
        dirs.push(DirNode {
            name: r.name.clone(),
            ctime: r.ctime,
            mt: r.mtime,
            own_sz: 0,
            own_n: 0,
            own_cat: None,
            own_t1: 0.0,
            own_t2: 0.0,
            fl: Vec::new(),
            children: Vec::new(),
        });
    }

    let root_dir_id = match dir_map.get(&5).copied() {
        Some(id) => id,
        None => {
            eprintln!("NO_ROOT_MAP");
            process::exit(5);
        }
    };

    for (idx, r) in recs.iter().enumerate() {
        let idx64 = idx as u64;
        if !r.valid {
            continue;
        }
        if idx64 == 5 || idx64 < 24 || r.is_reparse || !r.has_name || r.name.is_empty() {
            continue;
        }
        if r.parent == idx64 {
            continue;
        }
        if r.is_dir {
            if let (Some(&c_id), Some(&p_id)) = (dir_map.get(&idx64), dir_map.get(&r.parent)) {
                if c_id != p_id {
                    dirs[p_id as usize].children.push(c_id);
                }
            }
        } else if let Some(&p_id) = dir_map.get(&r.parent) {
            let p = &mut dirs[p_id as usize];
            p.own_sz += r.size;
            p.own_n += 1;
            let k = cat_of(&r.name);
            let cat = p.own_cat.get_or_insert([0u64; NCAT]);
            cat[k] += r.size;
            if r.mtime > p.own_t1 {
                p.own_t1 = r.mtime;
            }
            if r.atime > p.own_t2 {
                p.own_t2 = r.atime;
            }
            if r.size >= keep_bytes {
                p.fl.push((r.name.clone(), r.size, r.ctime, r.mtime, r.atime));
            }
        }
    }

    // Break any hypothetical cycles in parent pointers before dumping
    let mut state = vec![0u8; dirs.len()]; // 0=unvisited, 1=visiting, 2=done
    fn prune_cycles(u: u32, dirs: &mut [DirNode], state: &mut [u8]) {
        state[u as usize] = 1;
        let children = std::mem::take(&mut dirs[u as usize].children);
        let mut clean = Vec::with_capacity(children.len());
        for c in children {
            if state[c as usize] == 0 {
                clean.push(c);
                prune_cycles(c, dirs, state);
            }
        }
        dirs[u as usize].children = clean;
        state[u as usize] = 2;
    }
    prune_cycles(root_dir_id, &mut dirs, &mut state);

    let f = match File::create(out_json_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("OUT_ERR_{}", e);
            process::exit(6);
        }
    };
    let mut w = BufWriter::with_capacity(1 << 20, f);
    if let Err(e) = dump_dir(&mut w, root_dir_id, &dirs, Some(root_path)) {
        eprintln!("WRITE_ERR_{}", e);
        process::exit(6);
    }
    if let Err(e) = w.flush() {
        eprintln!("FLUSH_ERR_{}", e);
        process::exit(6);
    }
    println!("P {} {} 100", files_seen, bytes_seen);
    let _ = std::io::stdout().flush();
}
