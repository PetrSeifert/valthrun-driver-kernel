use std::{
    env::{
        self,
        var,
    },
    ffi::OsStr,
    fs::File,
    io::Write,
    path::{
        Path,
        PathBuf,
    },
};

use anyhow::Context;
use winreg::{
    enums::*,
    types::FromRegValue,
    RegKey,
    HKEY,
};

fn read_registry_value<T: FromRegValue>(
    hkey: HKEY,
    path: impl AsRef<OsStr>,
    name: impl AsRef<OsStr>,
) -> Option<T> {
    let hkey = RegKey::predef(hkey);
    let value = hkey.open_subkey(path).ok()?.get_value(name).ok()?;

    Some(value)
}

fn get_windows_kits_dir() -> anyhow::Result<PathBuf> {
    if let Ok(wdk_content_root) = env::var("WDKContentRoot") {
        let path = Path::new(wdk_content_root.as_str());
        if path.is_dir() {
            return Ok(path.to_path_buf());
        }
        eprintln!(
            "WDKContentRoot was detected to be {}, but does not exist or is not a valid directory.",
            path.display()
        );
    }

    if let Ok(microsoft_kit_root) = env::var("MicrosoftKitRoot") {
        let path = Path::new(microsoft_kit_root.as_str());

        if !path.is_absolute() {
            eprintln!(
                "MicrosoftKitRoot({}) was found in environment, but is not an absolute path.",
                path.display()
            );
        } else if !path.is_dir() {
            eprintln!(
                "MicrosoftKitRoot({}) was found in environment, but does not exist or is not a \
                 valid directory.",
                path.display()
            );
        } else {
            let wdk_kit_version = env::var("WDKKitVersion").unwrap_or_else(|_| "10.0".to_string());
            let path = path.join("Windows Kits").join(wdk_kit_version);
            if path.is_dir() {
                return Ok(path);
            }
            eprintln!(
                "WDKContentRoot was detected to be {}, but does not exist or is not a valid \
                 directory.",
                path.display()
            );
        }
    }

    if let Some(path) = read_registry_value::<String>(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows Kits\Installed Roots",
        r"KitsRoot10",
    ) {
        return Ok(Path::new(path.as_str()).to_path_buf());
    }

    if let Some(path) = read_registry_value::<String>(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Wow6432Node\Microsoft\Windows Kits\Installed Roots",
        r"KitsRoot10",
    ) {
        return Ok(Path::new(path.as_str()).to_path_buf());
    }

    anyhow::bail!("No valid Windows Kit found");
}

fn get_km_dirs(windows_kits_dir: &PathBuf) -> anyhow::Result<(PathBuf, PathBuf)> {
    let libdir = Path::new(windows_kits_dir).join("lib");

    let readdir = libdir
        .read_dir()
        .context(format!("Failed to read lib dir at {}", libdir.display()))?;

    let max_libdir = readdir
        .filter_map(|dir| dir.ok())
        .map(|dir| dir.path())
        .filter(|dir| {
            dir.components()
                .last()
                .and_then(|c| c.as_os_str().to_str())
                .map(|c| c.starts_with("10.") && dir.join("km").is_dir())
                .unwrap_or(false)
        })
        .max()
        .ok_or_else(|| {
            anyhow::anyhow!("Can not find a valid km dir in `{:?}`", windows_kits_dir)
        })?;

    let version = max_libdir
        .file_name()
        .expect("expected to have a file name");

    Ok((
        max_libdir.join("km"),
        Path::new(windows_kits_dir)
            .join("Include")
            .join(version)
            .join("km"),
    ))
}

fn generate_bindings(include_dir: &Path) -> anyhow::Result<()> {
    let bindings = bindgen::builder()
        .header("include/headers.h")
        .allowlist_type("(.*)WSK.*")
        .allowlist_function("Wsk.*")
        .allowlist_type("(.*)WSK.*")
        .allowlist_var("(.*)WSK.*")
        .allowlist_type("SOCKADDR_INET")
        .allowlist_var("AF_.*")
        .allowlist_var("SOCK_.*")
        .allowlist_var("SO_.*")
        .allowlist_var("SOL_.*")
        .allowlist_item("IPPROTO")
        .allowlist_var("INADDR_ANY")
        .allowlist_var("in6addr_any")
        .clang_arg(format!("-I{}", include_dir.to_string_lossy()))
        .ignore_functions() /* Do not generate functions. We're looking them up at runtime. */
        .blocklist_type("UNICODE_STRING")
        .blocklist_type("IRP")
        .blocklist_type("_IRP")
        .ctypes_prefix("::core::ffi")
        .generate()
        .context("failed to generate bindings")?
        .to_string();

    let bindings = bindings
        .replace("::std::", "::core::")
        .replace(":: std ::", ":: core ::");

    let out_path = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let mut output = File::options()
        .create(true)
        .truncate(true)
        .write(true)
        .open(out_path.join("bindings.rs"))
        .context("failed to open output file")?;

    write!(&mut output, "{}", bindings)?;

    println!("cargo:rerun-if-changed=include/headers.h");
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let windows_kits_dir = get_windows_kits_dir().context("Failed to get Windows kits dir")?;
    let (km_lib, km_include) = get_km_dirs(&windows_kits_dir).context("Failed to get km dirs")?;

    generate_bindings(&km_include)?;

    let target = var("TARGET").unwrap();
    let arch = if target.contains("x86_64") {
        "x64"
    } else if target.contains("i686") {
        "x86"
    } else {
        panic!("Only support x86_64 and i686!");
    };

    let lib_dir = km_lib.join(arch);
    println!(
        "cargo:rustc-link-search=native={}",
        lib_dir.to_str().unwrap()
    );

    Ok(())
}
