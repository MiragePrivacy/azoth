use crate::dataset::DatasetError;
use serde::{Deserialize, Serialize};
use std::path::Path;

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

/// Load the manifest from a local path, if present.
pub fn load_local_manifest(path: &Path) -> Result<Option<Manifest>, DatasetError> {
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read_to_string(path)?;
    let manifest = serde_json::from_str::<Manifest>(&data)?;
    Ok(Some(manifest))
}
