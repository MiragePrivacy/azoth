use async_trait::async_trait;
use azoth_analysis::dataset::{
    self, Dataset, DatasetError, DownloadManager, Manifest, Result as DatasetResult,
};
use clap::{Args, Subcommand};
use std::{error::Error, path::PathBuf};

/// Manage the Ethereum contracts dataset.
#[derive(Args)]
pub struct DatasetArgs {
    #[command(subcommand)]
    command: DatasetCommand,
    /// Override dataset root (default: ~/.azoth/datasets/ethereum_contracts).
    #[arg(long, value_name = "PATH")]
    dataset_root: Option<PathBuf>,
}

/// Subcommands for dataset management.
#[derive(Subcommand)]
pub enum DatasetCommand {
    /// Download the dataset and manifest.
    Download,
    /// Show dataset status and cached index info.
    Status,
    /// Verify downloaded files against the manifest.
    Verify,
    /// Rebuild the dataset comparison index.
    Reindex,
}

#[async_trait]
impl super::Command for DatasetArgs {
    async fn execute(self) -> Result<(), Box<dyn Error>> {
        let DatasetArgs {
            command,
            dataset_root,
        } = self;

        let root = dataset_root
            .clone()
            .unwrap_or_else(dataset::storage::dataset_root);

        match command {
            DatasetCommand::Download => download(root).await?,
            DatasetCommand::Status => status(root)?,
            DatasetCommand::Verify => verify(root)?,
            DatasetCommand::Reindex => reindex(root)?,
        }

        Ok(())
    }
}

async fn download(root: PathBuf) -> DatasetResult<()> {
    std::fs::create_dir_all(&root)?;
    let manifest = dataset::manifest::fetch_manifest().await?;
    persist_manifest(&root, &manifest)?;
    println!("Files to download: {}", manifest.files.len());
    for file in &manifest.files {
        if let Some(size) = file.size {
            println!("  {} ({} bytes)", file.name, size);
        } else {
            println!("  {}", file.name);
        }
    }
    let downloader = DownloadManager::new(root, true);
    for (idx, file) in manifest.files.iter().enumerate() {
        if downloader.verify_file(file)? {
            println!("Skip (hash ok): {}", file.name);
            continue;
        }
        println!(
            "Downloading [{}/{}]: {}",
            idx + 1,
            manifest.files.len(),
            file.name
        );
        downloader.download_file(file).await.map_err(|err| {
            DatasetError::Format(format!("download failed for {}: {err}", file.name))
        })?;
        println!("Downloaded: {}", file.name);
    }
    Ok(())
}

fn status(root: PathBuf) -> DatasetResult<()> {
    let manifest_path = dataset::storage::manifest_path(&root);
    let index_path = dataset::index_path(Some(root.clone()));
    let parquet_files = dataset::storage::list_parquet_files(&root)?;

    println!("Dataset root:   {}", root.display());
    println!(
        "Manifest:       {}",
        if manifest_path.exists() {
            "present"
        } else {
            "missing"
        }
    );
    println!("Parquet files:  {}", parquet_files.len());
    println!(
        "Index:          {}",
        if index_path.exists() {
            "present"
        } else {
            "missing"
        }
    );

    Ok(())
}

fn verify(root: PathBuf) -> DatasetResult<()> {
    let manifest_path = dataset::storage::manifest_path(&root);
    let manifest = dataset::manifest::load_local_manifest(&manifest_path)?
        .ok_or(DatasetError::MissingManifest)?;
    let downloader = DownloadManager::new(root, false);

    let mut ok = 0usize;
    let mut missing = 0usize;
    let mut bad = 0usize;

    for file in &manifest.files {
        match downloader.verify_file(file) {
            Ok(true) => ok += 1,
            Ok(false) => missing += 1,
            Err(_) => bad += 1,
        }
    }

    println!("Verified: {ok}");
    println!("Missing:  {missing}");
    println!("Bad:      {bad}");

    Ok(())
}

fn reindex(root: PathBuf) -> DatasetResult<()> {
    let dataset = Dataset::load(Some(root.clone()))?;
    let index = dataset::index::build_index(&dataset)?;
    dataset::save_index(Some(root), &index)?;
    Ok(())
}

fn persist_manifest(root: &std::path::Path, manifest: &Manifest) -> DatasetResult<()> {
    let path = dataset::storage::manifest_path(root);
    let data = serde_json::to_string_pretty(manifest)?;
    std::fs::write(path, data)?;
    Ok(())
}
