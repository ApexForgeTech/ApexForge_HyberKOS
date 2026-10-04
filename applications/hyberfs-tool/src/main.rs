use hyber_fs::{FileDevice, Volume};
use std::env;

fn usage() {
    eprintln!("usage:");
    eprintln!("  hyberfs-tool format <image> <blocks> --force");
    eprintln!("  hyberfs-tool check <image> <blocks>");
    eprintln!("  hyberfs-tool mkdir <image> <blocks> <path>");
    eprintln!("  hyberfs-tool touch <image> <blocks> <path>");
    eprintln!("  hyberfs-tool write <image> <blocks> <path> <text>");
    eprintln!("  hyberfs-tool cat <image> <blocks> <path>");
    eprintln!("  hyberfs-tool ls <image> <blocks> <path>");
}

fn blocks(s: &str) -> Result<u64, String> {
    s.parse().map_err(|_| "blocks must be an integer".into())
}
fn open(path: &str, blocks: u64) -> Result<Volume<FileDevice>, String> {
    Volume::mount(FileDevice::open(path, blocks).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("hyberfs-tool: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let a: Vec<String> = env::args().collect();
    let result = match a.get(1).map(String::as_str) {
        Some("format") if a.len() == 5 && a[4] == "--force" => {
            let d = FileDevice::open(&a[2], blocks(&a[3])?).map_err(|e| e.to_string())?;
            Volume::format(d).map(|_| ()).map_err(|e| e.to_string())
        }
        Some("check") if a.len() == 4 => {
            open(&a[2], blocks(&a[3])?).and_then(|v| v.check().map_err(|e| e.to_string()))
        }
        Some("mkdir") if a.len() == 5 => {
            let mut v = open(&a[2], blocks(&a[3])?)?;
            v.create_dir(&a[4], 0o755).map_err(|e| e.to_string())?;
            v.sync().map_err(|e| e.to_string())
        }
        Some("touch") if a.len() == 5 => {
            let mut v = open(&a[2], blocks(&a[3])?)?;
            v.create_file(&a[4], 0o644).map_err(|e| e.to_string())?;
            v.sync().map_err(|e| e.to_string())
        }
        Some("write") if a.len() == 6 => {
            let mut v = open(&a[2], blocks(&a[3])?)?;
            v.write_file(&a[4], 0, a[5].as_bytes())
                .map_err(|e| e.to_string())?;
            v.sync().map_err(|e| e.to_string())
        }
        Some("cat") if a.len() == 5 => {
            let v = open(&a[2], blocks(&a[3])?)?;
            let n = v.stat(&a[4]).map_err(|e| e.to_string())?.size as usize;
            let mut b = vec![0; n];
            v.read_file(&a[4], 0, &mut b)
                .map_err(|e| e.to_string())
                .map(|_| print!("{}", String::from_utf8_lossy(&b)))
        }
        Some("ls") if a.len() == 5 => {
            let v = open(&a[2], blocks(&a[3])?)?;
            v.list(&a[4]).map_err(|e| e.to_string()).map(|xs| {
                for (n, i) in xs {
                    println!("{}\t{:?}\t{}", n, i.kind, i.size);
                }
            })
        }
        _ => {
            usage();
            return Ok(());
        }
    };
    result
}
