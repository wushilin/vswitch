use ahash::RandomState as AHashState;
use fxhash::FxBuildHasher;
use std::collections::HashMap;
use std::collections::hash_map::RandomState as StdRandomState;
use std::env;
use std::hash::BuildHasher;
use std::hint::black_box;
use std::time::{Duration, Instant};

type Mac = [u8; 6];

#[derive(Clone, Copy)]
struct BenchConfig {
    ops: usize,
    keys: usize,
    mode: BenchMode,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BenchMode {
    Both,
    Put,
    Get,
}

struct BenchResult {
    name: &'static str,
    put: Option<(Duration, f64)>,
    get: Option<(Duration, f64)>,
}

fn main() {
    let cfg = parse_args().unwrap_or_else(|msg| {
        eprintln!("{msg}");
        eprintln!("Usage: cargo run --bin hashmap_bench -- [--ops N] [--keys K] [--mode both|put|get]");
        eprintln!("Defaults: --ops 5000000 --keys 20000");
        std::process::exit(2);
    });

    let keys = generate_keys(cfg.keys);
    println!("HashMap benchmark (6-byte keys)");
    println!(
        "keys: {}, ops: {}, mode: {}",
        cfg.keys,
        cfg.ops,
        mode_name(cfg.mode)
    );
    println!();

    let std_res = run_bench::<StdRandomState>("std::HashMap", &keys, cfg.ops, cfg.mode);
    let ahash_res = run_bench::<AHashState>("ahash::AHashMap", &keys, cfg.ops, cfg.mode);
    let fxhash_res = run_bench::<FxBuildHasher>("fxhash::FxHashMap", &keys, cfg.ops, cfg.mode);

    print_result(&std_res);
    print_result(&ahash_res);
    print_result(&fxhash_res);
}

fn parse_args() -> Result<BenchConfig, String> {
    let mut cfg = BenchConfig {
        ops: 5_000_000,
        keys: 20_000,
        mode: BenchMode::Both,
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
            "--help" | "-h" => {
                return Err("help requested".to_string());
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    if cfg.keys == 0 {
        return Err("--keys must be > 0".to_string());
    }
    if cfg.ops == 0 {
        return Err("--ops must be > 0".to_string());
    }
    Ok(cfg)
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

fn parse_positive_usize(s: &str, name: &str) -> Result<usize, String> {
    let v = s
        .parse::<usize>()
        .map_err(|_| format!("invalid value for {name}: {s}"))?;
    if v == 0 {
        return Err(format!("{name} must be > 0"));
    }
    Ok(v)
}

fn generate_keys(count: usize) -> Vec<Mac> {
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let x = i as u64;
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

fn run_bench<H: BuildHasher + Default>(
    name: &'static str,
    keys: &[Mac],
    ops: usize,
    mode: BenchMode,
) -> BenchResult {
    let put = if mode == BenchMode::Both || mode == BenchMode::Put {
        Some(run_put::<H>(keys, ops))
    } else {
        None
    };
    let get = if mode == BenchMode::Both || mode == BenchMode::Get {
        Some(run_get::<H>(keys, ops))
    } else {
        None
    };
    BenchResult { name, put, get }
}

fn run_put<H: BuildHasher + Default>(keys: &[Mac], ops: usize) -> (Duration, f64) {
    let mut map: HashMap<Mac, u64, H> =
        HashMap::with_capacity_and_hasher(keys.len() * 2, H::default());
    let mut put_rng = 0x0123_4567_89ab_cdefu64;
    let put_start = Instant::now();
    for i in 0..ops {
        put_rng = put_rng
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let idx = (put_rng as usize) % keys.len();
        let key = keys[idx];
        map.insert(key, i as u64);
    }
    let put_total = put_start.elapsed();
    black_box(map.len());
    (put_total, nanos_per_op(put_total, ops))
}

fn run_get<H: BuildHasher + Default>(keys: &[Mac], ops: usize) -> (Duration, f64) {
    let mut map: HashMap<Mac, u64, H> =
        HashMap::with_capacity_and_hasher(keys.len() * 2, H::default());
    for (idx, key) in keys.iter().enumerate() {
        map.insert(*key, idx as u64);
    }
    let mut get_rng = 0xfedc_ba98_7654_3210u64;
    let get_start = Instant::now();
    let mut checksum = 0u64;
    for _ in 0..ops {
        get_rng = get_rng
            .wrapping_mul(2862933555777941757)
            .wrapping_add(3037000493);
        let idx = (get_rng as usize) % keys.len();
        let key = keys[idx];
        let v = map
            .get(&key)
            .expect("internal benchmark error: get miss in 100% hit mode");
        checksum ^= *v;
    }
    let get_total = get_start.elapsed();
    black_box(checksum);
    (get_total, nanos_per_op(get_total, ops))
}

fn nanos_per_op(d: Duration, ops: usize) -> f64 {
    (d.as_nanos() as f64) / (ops as f64)
}

fn print_result(r: &BenchResult) {
    println!("{}", r.name);
    if let Some((total, ns_per_op)) = r.put {
        println!(
            "  put: total = {:>10.3} ms, ns/op = {:>8.2}",
            total.as_secs_f64() * 1_000.0,
            ns_per_op
        );
    }
    if let Some((total, ns_per_op)) = r.get {
        println!(
            "  get: total = {:>10.3} ms, ns/op = {:>8.2}",
            total.as_secs_f64() * 1_000.0,
            ns_per_op
        );
    }
    println!();
}
