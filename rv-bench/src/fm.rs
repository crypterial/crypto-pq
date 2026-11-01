// The timing driver: the list of (case, implementation) entries, crypto-pq's timing loop (batches
// grow until one second has passed, the mean per operation is reported), and two modes:
//   check                 byte checks only, then the list of entries
//   cpu [--rounds=N]      every case runs each implementation back to back, the order rotating
//                         every round
//   pair [--rounds=N] [--ms=M]  the paired design (see pair)
// Filters (any other argument) select cases by substring; --skip=IMP drops an implementation.

#![allow(dead_code)]

use std::time::{Duration, Instant};

pub type Batch = Box<dyn FnMut(u64) -> Duration>;

pub type Check = Result<(), String>;

// SHA_MIN_MS sets the minimum time per entry (default 1000 ms).
pub fn min_time() -> Duration {
    let ms = std::env::var("SHA_MIN_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(1000);

    Duration::from_millis(ms)
}

pub struct Entry {
    pub case: String,
    pub imp: String,
    pub batch: Batch,
}

pub struct List {
    pub entries: Vec<Entry>,
    pub lean: fn(&str) -> bool,
    pub filters: Vec<String>,
    pub skips: Vec<String>,
    pub mismatches: Vec<String>,
    pub checks: usize,
}

impl List {
    pub fn wants(&self, case: &str, imp: &str) -> bool {
        self.wants_case(case) && !self.skips.iter().any(|s| imp == s.as_str())
    }

    // The measurement's case list, then the substring filters.
    pub fn wants_case(&self, case: &str) -> bool {
        if !(self.lean)(case) {
            return false;
        }

        self.filters.is_empty() || self.filters.iter().any(|f| case.contains(f.as_str()))
    }

    // Whether any case of a parameter set ("ML-KEM-768") is wanted, so that a set none of whose
    // cases run is not even set up.
    pub fn family(&self, label: &str) -> bool {
        ["keygen", "encaps", "decaps", "sign", "verify"].iter().any(|operation| self.wants_case(&format!("{label}/{operation}")))
    }

    // KC_MAIN=1 (the build against crypto-pq main): only crypto-pq's own rows, labelled "main ...";
    // KC_MAIN=<name> (a variant build): labelled "<name> ...".
    pub fn add(&mut self, case: &str, imp: &str, batch: impl FnMut(u64) -> Duration + 'static) {
        let main = std::env::var("KC_MAIN").ok();

        if main.is_some() && !imp.starts_with("crypto-pq") {
            return;
        }

        let label = match main.as_deref() {
            None => imp.to_string(),
            Some("1") => format!("main {imp}"),
            Some(name) => format!("{name} {imp}"),
        };

        if self.wants(case, imp) {
            self.entries.push(Entry {
                case: case.to_string(),
                imp: label,
                batch: Box::new(batch),
            });
        }
    }

    pub fn report(&mut self, imp: &str, label: &str, result: Check) {
        self.check(imp, label, result);
    }

    pub fn check(&mut self, imp: &str, label: &str, result: Check) -> bool {
        self.checks += 1;

        match result {
            Ok(()) => true,
            Err(message) => {
                let line = format!("MISMATCH\t{imp}\t{label}: {message}");

                eprintln!("{line}");

                println!("{line}");

                self.mismatches.push(line);

                false
            }
        }
    }

    pub fn same(&mut self, case: &str, imp: &str, actual: &[u8], expected: &[u8]) -> bool {
        let result = if actual == expected {
            Ok(())
        } else {
            Err("output differs from crypto-pq".to_string())
        };

        self.check(imp, case, result)
    }

    pub fn note(&self, imp: &str, label: &str) {
        println!("NOTE\t{imp}\t{label}");
    }
}

pub fn timed(count: u64, mut operation: impl FnMut()) -> Duration {
    let start = Instant::now();

    for _ in 0..count {
        operation();
    }

    start.elapsed()
}

pub fn measure(batch: &mut Batch) -> (u64, f64) {
    let mut iterations = 0u64;

    let mut elapsed = Duration::ZERO;

    let mut count = 1u64;

    let min = min_time();

    while elapsed < min {
        elapsed += batch(count);

        iterations += count;

        let per_operation = elapsed.as_secs_f64() / iterations as f64;

        let remaining = min.saturating_sub(elapsed).as_secs_f64();

        count = ((remaining / per_operation).ceil() as u64).clamp(1, 10 * iterations);
    }

    (iterations, elapsed.as_secs_f64() * 1e6 / iterations as f64)
}

pub fn bytes(length: usize) -> Vec<u8> {
    (0..length).map(|i| i as u8).collect()
}

pub fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn same(what: &str, a: &[u8], b: &[u8]) -> Check {
    if a == b {
        Ok(())
    } else {
        Err(format!("{what}: output differs from crypto-pq"))
    }
}

fn cpu(list: &mut List, rounds: usize, offset: usize) {
    let mut cases: Vec<String> = Vec::new();

    for entry in &list.entries {
        if !cases.contains(&entry.case) {
            cases.push(entry.case.clone());
        }
    }

    for round in 0..rounds {
        for case in &cases {
            let mut indices: Vec<usize> = (0..list.entries.len()).filter(|&i| &list.entries[i].case == case).collect();

            let length = indices.len();

            indices.rotate_left((round + offset) % length);

            for i in indices {
                let (iterations, micros) = measure(&mut list.entries[i].batch);

                println!("R{}\t{}\t{}\t{}\t{:.4}", round + offset + 1, case, list.entries[i].imp, iterations, micros);
            }
        }
    }
}

// Paired: per case, every implementation runs the same count (about MS milliseconds on crypto-pq)
// back to back in each round, the order rotating with the round and the case; one line per
// implementation and round, so that each round gives every rival's time over crypto-pq's.
fn pair(list: &mut List, rounds: usize, ms: u64) {
    let mut cases: Vec<String> = Vec::new();

    for entry in &list.entries {
        if !cases.contains(&entry.case) {
            cases.push(entry.case.clone());
        }
    }

    let target = Duration::from_millis(ms);

    let mut plan = Vec::new();

    for case in &cases {
        let indices: Vec<usize> = (0..list.entries.len()).filter(|&i| &list.entries[i].case == case).collect();

        let Some(&ours) = indices.iter().find(|&&i| list.entries[i].imp == "crypto-pq") else {
            continue;
        };

        let mut count = 1u64;

        loop {
            let elapsed = (list.entries[ours].batch)(count);

            if elapsed >= target / 4 || count >= 1 << 30 {
                let least = elapsed.min((list.entries[ours].batch)(count)).min((list.entries[ours].batch)(count));

                count = ((target.as_secs_f64() * count as f64 / least.as_secs_f64()).ceil() as u64).max(1);

                break;
            }

            count *= 4;
        }

        let ours_per = (list.entries[ours].batch)(count).as_secs_f64() / count as f64;

        // A rival that takes more than twice our time per operation runs about the target time,
        // not our count, and its ratio is per operation all the same.
        let counts: Vec<(usize, u64)> = indices
            .iter()
            .map(|&i| {
                let per = (list.entries[i].batch)(1).as_secs_f64();

                let own = if per > 2.0 * ours_per {
                    ((target.as_secs_f64() / per).ceil() as u64).clamp(1, count)
                } else {
                    count
                };

                (i, own)
            })
            .collect();

        plan.push((case.clone(), counts));
    }

    // A case stops after 3 rounds once its rounds have taken PAIR_BUDGET_S seconds (default 3), so
    // that rivals far behind (seconds per operation) do not take the run's time.
    let budget = std::env::var("PAIR_BUDGET_S").ok().and_then(|v| v.parse().ok()).unwrap_or(3.0);

    let mut spent = vec![0.0f64; plan.len()];

    for round in 0..rounds {
        for (c, (case, counts)) in plan.iter().enumerate() {
            if round >= 3 && spent[c] > budget {
                continue;
            }

            let mut order = counts.clone();

            let length = order.len();

            order.rotate_left((round + c) % length);

            if (round / length) % 2 == 1 {
                order.reverse();
            }

            for (i, count) in order {
                let elapsed = (list.entries[i].batch)(count).as_secs_f64();

                spent[c] += elapsed;

                let micros = elapsed * 1e6 / count as f64;

                println!("P\t{round}\t{case}\t{}\t{count}\t{micros:.4}", list.entries[i].imp);
            }
        }
    }
}

// Runs the driver on a thread with a 256 MiB stack (ML-DSA and SLH-DSA keep large buffers on it).
pub fn main(lean: fn(&str) -> bool, build: fn(&mut List)) {
    std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(move || run(lean, build))
        .unwrap()
        .join()
        .unwrap();
}

fn run(lean: fn(&str) -> bool, build: fn(&mut List)) {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let mode = args.first().cloned().unwrap_or_default();

    let mut rounds = 3usize;

    let mut offset = 0usize;

    let mut ms = 20u64;

    let mut list = List {
        entries: Vec::new(),
        lean,
        filters: Vec::new(),
        skips: Vec::new(),
        mismatches: Vec::new(),
        checks: 0,
    };

    for arg in args.iter().skip(1) {
        if let Some(value) = arg.strip_prefix("--rounds=") {
            rounds = value.parse().unwrap();
        } else if let Some(value) = arg.strip_prefix("--ms=") {
            ms = value.parse().unwrap();
        } else if let Some(value) = arg.strip_prefix("--offset=") {
            offset = value.parse().unwrap();
        } else if let Some(value) = arg.strip_prefix("--skip=") {
            list.skips.push(value.to_string());
        } else if !arg.starts_with("--") {
            list.filters.push(arg.clone());
        }
    }

    build(&mut list);

    println!("CHECKS\tchecks={}\tmismatches={}\tentries={}", list.checks, list.mismatches.len(), list.entries.len());

    match mode.as_str() {
        "check" => {
            for entry in &list.entries {
                println!("ENTRY\t{}\t{}", entry.case, entry.imp);
            }
        }
        "cpu" => cpu(&mut list, rounds, offset),
        "pair" => pair(&mut list, rounds, ms),
        _ => panic!("mode: check | cpu"),
    }
}
