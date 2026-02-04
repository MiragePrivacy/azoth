use async_trait::async_trait;
use azoth_analysis::dataset::{
    self, Dataset, DatasetError, DownloadManager, Result as DatasetResult,
};
use clap::{Args, Subcommand};
use std::{collections::HashSet, error::Error, path::PathBuf};

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
    /// Download the dataset files.
    Download {
        /// Start block for download selection.
        #[arg(long, value_name = "BLOCK")]
        block_start: Option<u64>,
        /// Block range length for download selection.
        #[arg(long, value_name = "BLOCKS")]
        block_range: Option<u64>,
    },
    /// Show dataset status and cached index info.
    Status,
    /// Show dataset statistics from the cached index.
    Stats,
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
            DatasetCommand::Download {
                block_start,
                block_range,
            } => download(root, block_start, block_range).await?,
            DatasetCommand::Status => status(root)?,
            DatasetCommand::Stats => stats(root)?,
            DatasetCommand::Reindex => reindex(root)?,
        }

        Ok(())
    }
}

async fn download(
    root: PathBuf,
    block_start: Option<u64>,
    block_range: Option<u64>,
) -> DatasetResult<()> {
    println!(
        "Note: `azoth dataset download` currently fetches the Paradigm dataset only, \
which is incomplete and covers blocks 0 to 16,000,000."
    );
    std::fs::create_dir_all(&root)?;
    let manifest = dataset::manifest::fetch_manifest().await?;
    let mut files = manifest.files;

    if let Some(start) = block_start {
        let range = block_range.unwrap_or(0);
        if range == 0 {
            println!("Block range must be greater than 0.");
            return Ok(());
        }
        let end = start.saturating_add(range.saturating_sub(1));
        println!("Using block range: {}-{}", start, end);
        files.retain(|file| {
            dataset::storage::parse_file_block_range(&file.name)
                .map(|(file_start, file_end)| !(end < file_start || start > file_end))
                .unwrap_or(false)
        });
    } else if block_range.is_some() {
        println!("Block range ignored without --block-start.");
    }

    let local_files = dataset::storage::list_parquet_files(&root)?;
    let local_names = local_files
        .iter()
        .filter_map(|path| path.file_name().and_then(|name| name.to_str()))
        .map(|name| name.to_string())
        .collect::<HashSet<_>>();

    println!("Files to download: {}", files.len());
    for file in &files {
        if let Some(size) = file.size {
            println!("  {} ({} bytes)", file.name, size);
        } else {
            println!("  {}", file.name);
        }
    }
    let downloader = DownloadManager::new(root, true);
    for (idx, file) in files.iter().enumerate() {
        if local_names.contains(&file.name) {
            println!("Skip (exists): {}", file.name);
            continue;
        }
        println!("Downloading [{}/{}]: {}", idx + 1, files.len(), file.name);
        downloader.download_file(file).await.map_err(|err| {
            DatasetError::Format(format!("download failed for {}: {err}", file.name))
        })?;
        println!("Downloaded: {}", file.name);
    }
    Ok(())
}

fn status(root: PathBuf) -> DatasetResult<()> {
    let index_path = dataset::index_path(Some(root.clone()));
    let parquet_files = dataset::storage::list_parquet_files(&root)?;

    println!("Dataset root:   {}", root.display());
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

fn stats(root: PathBuf) -> DatasetResult<()> {
    let index = dataset::load_index(Some(root))?;
    println!("Total contracts: {}", index.total_count);
    println!("Size bucket:     {} bytes", index.size_bucket_bytes);
    println!("Block bucket:    {} blocks", index.block_bucket_size);

    if !index.runtime_size_buckets.is_empty() {
        println!();
        println!("Runtime size distribution:");
        for bucket in &index.runtime_size_buckets {
            let end = bucket.start as u64 + index.size_bucket_bytes - 1;
            println!("  {}-{} bytes: {}", bucket.start, end, bucket.count);
        }
    }

    if !index.init_size_buckets.is_empty() {
        println!();
        println!("Init code size distribution:");
        for bucket in &index.init_size_buckets {
            let end = bucket.start as u64 + index.size_bucket_bytes - 1;
            println!("  {}-{} bytes: {}", bucket.start, end, bucket.count);
        }
    }

    if !index.block_buckets.is_empty() {
        println!();
        println!("Deployment block distribution:");
        for bucket in &index.block_buckets {
            let end = bucket.start + index.block_bucket_size - 1;
            println!("  {}-{}: {}", bucket.start, end, bucket.count);
        }
    }

    if !index.compiler_versions.is_empty() {
        println!();
        println!("Compiler versions (top 20):");
        let mut versions = index.compiler_versions.clone();
        versions.sort_by(|a, b| b.count.cmp(&a.count));
        for entry in versions.into_iter().take(20) {
            println!("  {}: {}", entry.version, entry.count);
        }
    }

    Ok(())
}

fn reindex(root: PathBuf) -> DatasetResult<()> {
    let dataset = Dataset::load(Some(root.clone()))?;
    let index = dataset::index::build_index(&dataset)?;
    dataset::save_index(Some(root), &index)?;
    Ok(())
}
