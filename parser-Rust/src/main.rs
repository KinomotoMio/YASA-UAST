use std::process;

fn main() {
    match uast4rust::parse_args() {
        Ok(cli) => {
            if let Err(err) = uast4rust::run(&cli) {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Err(uast4rust::ParseArgsError::HelpRequested) => {
            println!("{}", uast4rust::usage());
        }
        Err(err) => {
            eprintln!("{err}");
            process::exit(2);
        }
    }
}
