//! Dependency-free harness baseline; this is not Signal pipeline throughput.

use std::{error::Error, hint::black_box, time::Instant};

fn main() -> Result<(), Box<dyn Error>> {
    let iterations = match std::env::var("SIGNAL_BENCH_ITERATIONS") {
        Ok(value) => value.parse::<u64>()?,
        Err(std::env::VarError::NotPresent) => 100_000,
        Err(error) => return Err(error.into()),
    };
    if iterations == 0 {
        return Err("SIGNAL_BENCH_ITERATIONS must be positive".into());
    }
    let start = Instant::now();
    for iteration in 0..iterations {
        black_box(iteration);
    }
    println!(
        "harness_baseline iterations={iterations} elapsed_ns={}",
        start.elapsed().as_nanos()
    );
    Ok(())
}
