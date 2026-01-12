use std::path::{Path, PathBuf};

const DATASET_ENV_VAR: &str = "AZOTH_DATASET_DIR";
const DATASET_SUBDIR: &str = "ethereum_contracts";

/// Resolve the dataset root directory, honoring AZOTH_DATASET_DIR if set.
/// Defaults to ./.azoth/datasets/ethereum_contracts relative to the current directory.
pub fn dataset_root() -> PathBuf {
    if let Ok(path) = std::env::var(DATASET_ENV_VAR) {
        return PathBuf::from(path);
    }

    let base = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    base.join(".azoth").join("datasets").join(DATASET_SUBDIR)
}

/// Ensure the dataset directory exists.
pub fn ensure_dataset_dir() -> std::io::Result<PathBuf> {
    let root = dataset_root();
    std::fs::create_dir_all(&root)?;
    Ok(root)
}

/// Resolve the manifest file path under the dataset root.
pub fn manifest_path(root: &Path) -> PathBuf {
    root.join("dataset_manifest.json")
}

/// Resolve the cached index path under the dataset root.
pub fn index_path(root: &Path) -> PathBuf {
    root.join("index.json")
}

/// List parquet files under the dataset root.
pub fn list_parquet_files(root: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    if !root.exists() {
        return Ok(files);
    }

    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("parquet") {
            files.push(path);
        }
    }

    files.sort();
    Ok(files)
}
