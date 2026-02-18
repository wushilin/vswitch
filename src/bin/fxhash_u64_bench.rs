use fxhash::FxBuildHasher;
use std::collections::HashMap;
use std::env;
use std::hint::black_box;
use std::time::Instant;

#[derive(Clone, Copy, PartialEq, Eq)]
enum BenchMode {
    Both,
    Put,
    Get,
}

#[derive(Clone, Copy)]
struct BenchConfig {
    ops: usize,
    keys: usize,
    mode: BenchMode,
    pack_each_get: bool,
}

fn main() {
    let cfg = parse_args().unwrap_or_else(|msg| {
        eprintln!("{msg}");
        eprintln!("Usage: cargo run --bin fxhash_u64_bench -- [--ops N] [--keys K] [--mode both|put|get] [--pack-each-get]");
        eprintln!("Defaults: --ops 5000000 --keys 20000 --mode both (without per-get packing)");
        std::process::exit(2);
    });

    let mac_keys = generate_mac_keys(cfg.keys);
    let packed_keys = mac_keys
        .iter()
        .map(|m| pack_mac_to_u64(*m))
        .collect::<Vec<u64>>();
    println!("fxhash HashMap<u64, u64> benchmark (packed 6-byte keys)");
    println!(
        "keys: {}, ops: {}, mode: {}, pack_each_get: {}",
        cfg.keys,
        cfg.ops,
        mode_name(cfg.mode),
        cfg.pack_each_get
    );

    if cfg.mode == BenchMode::Both || cfg.mode == BenchMode::Put {
        let (total_ms, ns_per_op) = run_put(&packed_keys, cfg.ops);
        println!("put: total = {:.3} ms, ns/op = {:.2}", total_ms, ns_per_op);
    }
    if cfg.mode == BenchMode::Both || cfg.mode == BenchMode::Get {
        let (total_ms, ns_per_op) = run_get(&packed_keys, &mac_keys, cfg.ops, cfg.pack_each_get);
        println!("get: total = {:.3} ms, ns/op = {:.2}", total_ms, ns_per_op);
    }
}

fn parse_args() -> Result<BenchConfig, String> {
    let mut cfg = BenchConfig {
        ops: 5_000_000,
        keys: 20_000,
        mode: BenchMode::Both,
        pack_each_get: false,
    };
    let mut it = env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--ops" => {
                let v = it
                    .next()
                    .ok_or_else(|| "--ops requires a value".to_string())?;
                cfg.ops = parse_positive_usize(&v, "--ops")?;
            }
            "--keys" => {
                let v = it
                    .next()
                    .ok_or_else(|| "--keys requires a value".to_string())?;
                cfg.keys = parse_positive_usize(&v, "--keys")?;
            }
            "--mode" => {
                let v = it
                    .next()
                    .ok_or_else(|| "--mode requires a value".to_string())?;
                cfg.mode = parse_mode(&v)?;
            }
            "--pack-each-get" => cfg.pack_each_get = true,
            "--help" | "-h" => return Err("help requested".to_string()),
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    if cfg.ops == 0 || cfg.keys == 0 {
        return Err("--ops and --keys must be > 0".to_string());
    }
    Ok(cfg)
}

fn parse_positive_usize(s: &str, name: &str) -> Result<usize, String> {
    let v = s
        .parse::<usize>()
        .map_err(|_| format!("invalid value for {name}: {s}"))?;
    if v == 0 {
        return Err(format!("{name} must be > 0"));
    }
    Ok(v)
}

fn parse_mode(s: &str) -> Result<BenchMode, String> {
    match s {
        "both" => Ok(BenchMode::Both),
        "put" => Ok(BenchMode::Put),
        "get" => Ok(BenchMode::Get),
        _ => Err(format!("invalid --mode value: {s} (expected both|put|get)")),
    }
}

fn mode_name(mode: BenchMode) -> &'static str {
    match mode {
        BenchMode::Both => "both",
        BenchMode::Put => "put",
        BenchMode::Get => "get",
    }
}

fn generate_mac_keys(count: usize) -> Vec<[u8; 6]> {
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let x = (i as u64) & 0x0000_ffff_ffff;
        out.push([
            (x & 0xff) as u8,
            ((x >> 8) & 0xff) as u8,
            ((x >> 16) & 0xff) as u8,
            ((x >> 24) & 0xff) as u8,
            ((x >> 32) & 0xff) as u8,
            ((x >> 40) & 0xff) as u8,
        ]);
    }
    out
}

fn pack_mac_to_u64(mac: [u8; 6]) -> u64 {
    (mac[0] as u64)
        | ((mac[1] as u64) << 8)
        | ((mac[2] as u64) << 16)
        | ((mac[3] as u64) << 24)
        | ((mac[4] as u64) << 32)
        | ((mac[5] as u64) << 40)
}

fn run_put(keys: &[u64], ops: usize) -> (f64, f64) {
    let mut map: HashMap<u64, u64, FxBuildHasher> =
        HashMap::with_capacity_and_hasher(keys.len() * 2, FxBuildHasher::default());
    let mut rng = 0x0123_4567_89ab_cdefu64;
    let start = Instant::now();
    for i in 0..ops {
        rng = rng
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let idx = (rng as usize) % keys.len();
        map.insert(keys[idx], i as u64);
    }
    let d = start.elapsed();
    black_box(map.len());
    let total_ms = d.as_secs_f64() * 1000.0;
    let ns_per_op = (d.as_nanos() as f64) / (ops as f64);
    (total_ms, ns_per_op)
}

fn run_get(keys: &[u64], mac_keys: &[[u8; 6]], ops: usize, pack_each_get: bool) -> (f64, f64) {
    let mut map: HashMap<u64, u64, FxBuildHasher> =
        HashMap::with_capacity_and_hasher(keys.len() * 2, FxBuildHasher::default());
    for (i, k) in keys.iter().enumerate() {
        map.insert(*k, i as u64);
    }
    let mut rng = 0xfedc_ba98_7654_3210u64;
    let mut checksum = 0u64;
    let start = Instant::now();
    for _ in 0..ops {
        rng = rng.wrapping_mul(2862933555777941757).wrapping_add(3037000493);
        let idx = (rng as usize) % keys.len();
        let key = if pack_each_get {
            pack_mac_to_u64(mac_keys[idx])
        } else {
            keys[idx]
        };
        let v = map
            .get(&key)
            .expect("internal benchmark error: get miss in 100% hit mode");
        checksum ^= *v;
    }
    let d = start.elapsed();
    black_box(checksum);
    let total_ms = d.as_secs_f64() * 1000.0;
    let ns_per_op = (d.as_nanos() as f64) / (ops as f64);
    (total_ms, ns_per_op)
}
