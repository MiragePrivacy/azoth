use crate::dataset::DatasetError;
use serde::{Deserialize, Serialize};
const MANIFEST_URL: &str = "https://raw.githubusercontent.com/paradigmxyz/paradigm-data-portal/main/datasets/ethereum_contracts/dataset_manifest.json";

/// Dataset manifest metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// Files included in the dataset release.
    pub files: Vec<ManifestFile>,
    /// Optional version identifier.
    pub version: Option<String>,
}

/// Single dataset file entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestFile {
    /// Filename on the data portal.
    pub name: String,
    #[serde(rename = "hash")]
    /// MD5 hash as a lowercase hex string.
    pub md5: String,
    /// Optional file size in bytes.
    pub size: Option<u64>,
}

/// Fetch the manifest from the Paradigm data portal repository.
pub async fn fetch_manifest() -> Result<Manifest, DatasetError> {
    let response = reqwest::get(MANIFEST_URL).await?.error_for_status()?;
    let manifest = response.json::<Manifest>().await?;
    Ok(manifest)
}

// Intentionally no local manifest helpers: downloads should be driven by
// parquet filenames and requested block ranges.
