use std::io::{stderr, stdout};

fn main() {
    let code = smash_cli::run(std::env::args_os().skip(1), &mut stdout(), &mut stderr());
    std::process::exit(code);
}
