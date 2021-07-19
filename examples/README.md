# Example of using zettabgp

If you checkout this repository, you can build any of the examples (at this time - only bgpdumper) `cargo run --example example_name`.

### Dependencies

```toml
[dependencies]
zettabgp = { version = "0.1.4", features = ["full"] }
```

## Getting Started

### Minimal BGP dumper

* [`bgpdumper`](bgpdumper.rs) - A simple CLI application connects to specified BGP peer and prints incoming messages. Of course you should configure your BGP router first.
