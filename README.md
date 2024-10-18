# PSO2 RSA Injector (classic)

A "simple" RSA key swapper for PSO2 (tested only on NA). This project is based on [cyberkitsune's "PSO2KeyTools"](https://github.com/cyberkitsune/PSO2Proxy/tree/5355aea6edb5342a439642c892369443246c4644/tools).

If you are looking for an injector for the NGS version of the game, you can find it [here](https://github.com/AntonnMal/pso2-rsa-injector).

## Building

You will need to install [rust compiler](https://www.rust-lang.org/tools/install).

From Windows:
```
cargo build
```

From Linux (only for rsa replacer):
```
rustup target add x86_64-pc-windows-gnu # run if the windows toolchain is not installed
cargo build --target x86_64-pc-windows-gnu
```

## Usage

1) Generate a [key pair](https://github.com/cyberkitsune/PSO2Proxy#your-private--public-keypair).
2) (If the server doesn't support auto key negotiation) Copy your `publickey.blob` to `pso2_bin`.
3) (Optional) Copy `config.toml` to `pso2_bin` and edit it.
4) Copy `rsa_inject.dll` and `eos_gaming.dll` to `pso2_bin`
5) Launch the game.

## Notes

 - Code is generally lacking in comments.
