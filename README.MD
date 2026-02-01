# Valthrun Kernel Driver

This is the implementation for the Valthrun driver protocol as a kernel driver.

## Building the standalone driver

### Requirements

- Visual Studio 2022
- Windows Kernel Development Kit
- LLVM Compiler Infrastructure 
- Cargo and Rust Nightly

### Build the driver

Now, you will build the standalone driver from source. This will create an output at `target/x86_64-pc-windows-msvc/release/valthrun-driver.dll`.

```ps1
# Change your current directory into the standalone directory
# Make sure you are in this directory, NOT the parent one. Else you will get confusing compiler errors.
cd driver-standalone

# Create a release build
cargo build --verbose --r
```

### Stripping and Signing

Finally, you strip and sign the driver with a test signing certificate. There are two scripts you need to execute for that.

```ps1
# Make sure you're not in the `driver-standalone` directory
cd ..

# Strip the driver and output it to the correct location
& "./Strip-Driver.ps1" -InputFile ./target/x86_64-pc-windows-msvc/release/driver_standalone.dll -OutputFile ./target/x86_64-pc-windows-msvc/release/valthrun-driver.sys

# Sign the driver with a test-signing certificate
& "./Sign-Driver.ps1" ./target/x86_64-pc-windows-msvc/release/valthrun-driver.sys
```

The output will be located at `target/x86_64-pc-windows-msvc/release/valthrun-driver.sys`

## Mapping the driver

Now that you've built the driver, you can use KDMapper or test signing to map it.

- [KDMapper Guide](https://wiki.valth.run/drivers/implementation/kernel/loader/kdmapper/)
- [Test Signing Guide](https://wiki.valth.run/drivers/implementation/kernel/loader/test-signing/)
