# Valthrun Kernel Driver

This is the implementation for the Valthrun driver protocol as a kernel driver.

## Build

### Requirements

- Visual Studio 2022
- Windows Kernel Development Kit
- LLVM Compiler Infrastructure 
- Cargo Make (`cargo install --force cargo-make`)

### Build the driver

```ps1
# Go to ether the standalone or UEFI driver
cd driver-standalone

# Create a release build.
# The result will be located at "../target/x86_64-pc-windows-msvc/release/valthrun-driver.dll"
cargo b -r

# Now we Strip the driver to get valthrun-driver.sys via Strip-Driver.ps1 linking input to espected realese build "../target/x86_64-pc-windows-msvc/release/valthrun-driver.dll".
```
