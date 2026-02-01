use std::path::{
    Path,
    PathBuf,
};
use std::env;
use std::ffi::OsStr;

use winreg::{
    enums::*,
    RegKey,
    HKEY,
    types::FromRegValue
};

#[derive(Debug)]
pub struct WindowsKit {
    pub version: String,
    pub dir_root: PathBuf,

    pub dir_include: PathBuf,
    pub dir_libs: PathBuf,
}

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

fn find_latest_version(windows_kits_dir: &PathBuf) -> anyhow::Result<String> {
    let max_libdir = Path::new(windows_kits_dir)
        .join("lib")
        .read_dir()?
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

    Ok(max_libdir
        .file_name()
        .expect("expected to have a file name")
        .to_string_lossy()
        .to_string())
}

pub fn locate_wdk() -> anyhow::Result<WindowsKit> {
    let windows_kits_dir = get_windows_kits_dir()?;
    let version = find_latest_version(&windows_kits_dir)?;

    Ok(WindowsKit {
        dir_root: windows_kits_dir.clone(),
        dir_include: windows_kits_dir.join("Include").join(&version).join("km"),
        dir_libs: windows_kits_dir.join("lib").join(&version).join("km"),

        version,
    })
}

#[cfg(test)]
mod test {
    use crate::{
        find_latest_version,
        get_windows_kits_dir,
    };

    #[test]
    fn print_status() {
        let windows_kits_dir = get_windows_kits_dir().unwrap();
        let version = find_latest_version(&windows_kits_dir).unwrap();
        println!("WDK installation details");
        println!("Directory: {}", windows_kits_dir.display());
        println!("Version  : {}", version);
    }
}
