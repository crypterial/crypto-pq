// Rival measurement of crypto-pq categories 6 (BLAKE2, BLAKE3), 7 (Ascon) and 8 (FrodoKEM): crypto-pq
// (main), an A/A copy of it, and every counted rival crate, in one process. Before timing, every
// output is compared with crypto-pq's (byte for byte, or by cross-decapsulation); an implementation
// that differs is reported and left out of its row. Each round times one sample of every
// implementation of a row, the order rotating with the round.
// Usage: meas <blake|ascon|frodo|all> [rounds] [row filter]
// With feature flavor-base, the "crypto-pq" column is base and the A/A column is new.
#[cfg(not(any(feature = "flavor-base", feature = "flavor-aa")))]
extern crate cpq_new as cpq;

#[cfg(feature = "flavor-base")]
extern crate cpq_base as cpq;

#[cfg(feature = "flavor-aa")]
extern crate cpq_aa as cpq;

use std::hint::black_box;
use std::time::Instant;

// A row entry of a rival crate that does not build for the target becomes an unnamed entry, which
// run_hash_rows drops before the output check.
macro_rules! absent {
    ($($t:tt)*) => {
        ("", Box::new(|_: &[u8], _: &mut [u8]| unreachable!()))
    };
}

#[cfg(not(target_arch = "x86"))]
macro_rules! if_rscrypto {
    ($($t:tt)*) => { ($($t)*) };
}

#[cfg(target_arch = "x86")]
macro_rules! if_rscrypto {
    ($($t:tt)*) => { absent!() };
}

#[cfg(not(target_family = "wasm"))]
macro_rules! if_purecrypto {
    ($($t:tt)*) => { ($($t)*) };
}

#[cfg(target_family = "wasm")]
macro_rules! if_purecrypto {
    ($($t:tt)*) => { absent!() };
}

#[cfg(not(target_family = "wasm"))]
macro_rules! if_openssl {
    ($($t:tt)*) => { ($($t)*) };
}

#[cfg(target_family = "wasm")]
macro_rules! if_openssl {
    ($($t:tt)*) => { absent!() };
}

mod ascon;
mod blake;
mod frodo;

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

fn median(values: &mut [f64]) -> f64 {
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
    if std::env::var_os("PB_CHECK").is_some() {
        return;
    }

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
            if name.is_empty() {
                continue;
            }

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

        let mut imps: Vec<Imp> = kept
            .iter()
            .map(|(name, f)| {
                let mut buf = vec![0u8; out];

                Imp {
                    name,
                    run: Box::new(move || {
                        f(black_box(input), &mut buf);

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

    if category == "ascon" || category == "all" {
        run_hash_rows(ascon::rows(), rounds, filter, 1e6);
    }

    if category == "frodo" || category == "all" {
        frodo::run(rounds, filter);
    }
}
