// blake-ab: category 6 (BLAKE2, BLAKE3) A/B of a train: crypto-pq (new), an A/A copy, main,
// and every counted rival crate, in one process (from meas-eng's meas). Before timing, every
// output is compared with crypto-pq's (byte for byte, or by cross-decapsulation); an implementation
// that differs is reported and left out of its row. Each round times one sample of every
// implementation of a row, the order rotating with the round.
// Usage: blake-ab <blake|check|probe> [rounds] [row filter]
use std::hint::black_box;
use std::time::Instant;

mod blake;
mod check;
mod probe;

pub type HashFn<'a> = Box<dyn Fn(&[u8], &mut [u8]) + 'a>;

pub struct HashRow<'a> {
    pub label: String,
    pub input: Vec<u8>,
    pub out: usize,
    pub imps: Vec<(&'static str, HashFn<'a>)>,
}

pub struct Imp<'a> {
    pub name: &'static str,
    pub run: Box<dyn FnMut() + 'a>,
}

pub fn data(length: usize, tweak: u8) -> Vec<u8> {
    (0..length).map(|i| (i as u8).wrapping_mul(31).wrapping_add(tweak ^ (i >> 8) as u8)).collect()
}

pub fn median(values: &mut [f64]) -> f64 {
    values.sort_by(f64::total_cmp);

    let n = values.len();

    if n % 2 == 1 { values[n / 2] } else { (values[n / 2 - 1] + values[n / 2]) / 2.0 }
}

// ns per call of `run`, over `per` calls.
fn sample(run: &mut dyn FnMut(), per: u64) -> f64 {
    let start = Instant::now();

    for _ in 0..per {
        run();
    }

    start.elapsed().as_nanos() as f64 / per as f64
}

// One line per implementation: median ns, and the median, minimum and maximum over rounds of its
// time over crypto-pq's (above 1: crypto-pq takes less time).
pub fn time_row(label: &str, imps: &mut [Imp], rounds: usize, sample_ns: f64) {
    let n = imps.len();

    let mut per = vec![1u64; n];

    for (i, imp) in imps.iter_mut().enumerate() {
        sample(&mut imp.run, 1);

        let one = sample(&mut imp.run, 1).max(1.0);

        per[i] = ((sample_ns / one) as u64).clamp(1, 10_000_000);

        sample(&mut imp.run, per[i]);
    }

    let mut times = vec![vec![0.0; rounds]; n];

    for round in 0..rounds {
        let mut order: Vec<usize> = (0..n).map(|k| (k + round) % n).collect();

        if round % 2 == 1 {
            order.reverse();
        }

        for &i in &order {
            times[i][round] = sample(&mut imps[i].run, per[i]);
        }
    }

    for i in 0..n {
        let mut ratios: Vec<f64> = (0..rounds).map(|r| times[i][r] / times[0][r]).collect();

        let low = ratios.iter().copied().fold(f64::MAX, f64::min);

        let high = ratios.iter().copied().fold(0.0, f64::max);

        let mut ns = times[i].clone();

        println!(
            "R\t{label}\t{}\t{:.1}\t{:.4}\t{low:.4}\t{high:.4}",
            imps[i].name,
            median(&mut ns),
            median(&mut ratios)
        );
    }
}

pub fn run_hash_rows(rows: Vec<HashRow>, rounds: usize, filter: Option<&str>, sample_ns: f64) {
    for row in rows {
        if filter.is_some_and(|f| !row.label.contains(f)) {
            continue;
        }

        let mut reference = vec![0u8; row.out];

        (row.imps[0].1)(&row.input, &mut reference);

        let mut kept = Vec::new();

        for (name, f) in row.imps {
            if std::env::var_os("MEAS_TRACE").is_some() {
                eprintln!("check {} {name}", row.label);
            }

            let mut out = vec![0u8; row.out];

            f(&row.input, &mut out);

            if out == reference {
                kept.push((name, f));
            } else {
                println!("MISMATCH\t{}\t{name}", row.label);
            }
        }

        println!("CHECK\t{}\t{} implementations agree", row.label, kept.len());

        let input = &row.input;

        let out = row.out;

        // AB_SHIFT=n: every output buffer starts n bytes into its allocation (store aliasing check).
        let shift: usize = std::env::var("AB_SHIFT").ok().and_then(|v| v.parse().ok()).unwrap_or(0);

        let mut imps: Vec<Imp> = kept
            .iter()
            .map(|(name, f)| {
                let mut buf = vec![0u8; out + shift];

                Imp {
                    name,
                    run: Box::new(move || {
                        f(black_box(input), &mut buf[shift..]);

                        black_box(&buf);
                    }),
                }
            })
            .collect();

        time_row(&row.label, &mut imps, rounds, sample_ns);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let category = args.get(1).map_or("all", |s| s.as_str());

    let rounds: usize = args.get(2).map_or(16, |r| r.parse().unwrap());

    let filter = args.get(3).map(|s| s.as_str());

    if category == "blake" || category == "all" {
        run_hash_rows(blake::rows(), rounds, filter, 1e6);
    }

    if category == "check" {
        check::run();
    }

    if category == "probe" {
        probe::run();
    }
}
