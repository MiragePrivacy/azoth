use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;

pub mod download;
pub mod index;
pub mod manifest;
pub mod parquet;
pub mod storage;

pub use download::DownloadManager;
pub use index::{BlockFilter, DatasetIndex, SizeCount};
pub use manifest::{Manifest, ManifestFile};

/// Errors returned by dataset management helpers.
#[derive(Debug, Error)]
pub enum DatasetError {
    /// IO failure while reading or writing dataset files.
    #[error("dataset IO error: {0}")]
    Io(#[from] std::io::Error),
    /// HTTP failure while fetching remote data.
    #[error("dataset HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    /// JSON parsing failure for manifest or index.
    #[error("dataset JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// Parquet decoding error.
    #[error("dataset parquet error: {0}")]
    Parquet(#[from] ::parquet::errors::ParquetError),
    /// Arrow decoding error.
    #[error("dataset arrow error: {0}")]
    Arrow(#[from] arrow::error::ArrowError),
    /// Manifest is missing from the dataset directory.
    #[error("dataset manifest missing")]
    MissingManifest,
    /// Index is missing from the dataset directory.
    #[error("dataset index missing")]
    MissingIndex,
    /// A downloaded file failed integrity checks.
    #[error("dataset integrity check failed for {0}")]
    Integrity(String),
    /// Invalid or unexpected dataset format.
    #[error("dataset format error: {0}")]
    Format(String),
}

/// Result type for dataset operations.
pub type Result<T> = std::result::Result<T, DatasetError>;

/// Local dataset metadata and file location.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dataset {
    /// Dataset root directory.
    pub root: PathBuf,
    /// Manifest metadata.
    pub manifest: Manifest,
}

impl Dataset {
    /// Load the dataset manifest from the local cache.
    pub fn load(root: Option<PathBuf>) -> Result<Self> {
        let root = root.unwrap_or_else(storage::dataset_root);
        let manifest_path = storage::manifest_path(&root);
        let manifest =
            manifest::load_local_manifest(&manifest_path)?.ok_or(DatasetError::MissingManifest)?;
        Ok(Self { root, manifest })
    }

    pub fn is_available(root: Option<PathBuf>) -> bool {
        let root = root.unwrap_or_else(storage::dataset_root);
        storage::manifest_path(&root).exists()
    }

    /// List parquet files in the dataset cache.
    pub fn parquet_files(&self) -> Result<Vec<PathBuf>> {
        Ok(storage::list_parquet_files(&self.root)?)
    }

    /// Compute an MD5 hash of the local manifest for cache validation.
    pub fn manifest_hash(&self) -> Result<String> {
        let path = storage::manifest_path(&self.root);
        if !path.exists() {
            return Err(DatasetError::MissingManifest);
        }
        let bytes = std::fs::read(path)?;
        Ok(crate::dataset::index::md5_hex(&bytes))
    }
}

/// Load the cached dataset index from disk.
pub fn load_index(root: Option<PathBuf>) -> Result<DatasetIndex> {
    let root = root.unwrap_or_else(storage::dataset_root);
    let path = storage::index_path(&root);
    if !path.exists() {
        return Err(DatasetError::MissingIndex);
    }
    let data = std::fs::read_to_string(path)?;
    let index = serde_json::from_str::<DatasetIndex>(&data)?;
    Ok(index)
}

/// Persist a dataset index to disk.
pub fn save_index(root: Option<PathBuf>, index: &DatasetIndex) -> Result<()> {
    let root = root.unwrap_or_else(storage::dataset_root);
    std::fs::create_dir_all(&root)?;
    let path = storage::index_path(&root);
    let data = serde_json::to_string_pretty(index)?;
    std::fs::write(path, data)?;
    Ok(())
}

/// Resolve the cached index file path.
pub fn index_path(root: Option<PathBuf>) -> PathBuf {
    let root = root.unwrap_or_else(storage::dataset_root);
    storage::index_path(&root)
}
