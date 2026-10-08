mod daemon;
mod worker;
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let result = if args.first().is_some_and(|a| a == "--worker") && args.len() == 4 {
        args[2]
            .parse::<usize>()
            .and_then(|memory| args[3].parse::<usize>().map(|shares| (memory, shares)))
            .map_err(|_| "invalid worker limits".to_string())
            .and_then(|(memory, shares)| worker::run(&args[1], memory, shares))
    } else {
        daemon::run(&args)
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
