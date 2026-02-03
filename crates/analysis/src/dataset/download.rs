use crate::dataset::{Result, manifest::ManifestFile};
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::header::{HeaderMap, RANGE};
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;

/// Downloads dataset parquet files with optional progress output.
pub struct DownloadManager {
    client: reqwest::Client,
    root: PathBuf,
    show_progress: bool,
}

impl DownloadManager {
    /// Create a new downloader rooted at the dataset directory.
    pub fn new(root: PathBuf, show_progress: bool) -> Self {
        let client = reqwest::Client::new();
        Self {
            client,
            root,
            show_progress,
        }
    }

    /// Return the dataset root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Download a single parquet file, resuming if possible.
    pub async fn download_file(&self, file: &ManifestFile) -> Result<()> {
        std::fs::create_dir_all(&self.root)?;
        let path = self.root.join(&file.name);
        if path.exists() {
            return Ok(());
        }

        let mut headers = HeaderMap::new();
        let mut mode = DownloadMode::Fresh;
        if let Ok(metadata) = std::fs::metadata(&path) {
            let existing = metadata.len();
            if existing > 0 {
                headers.insert(RANGE, format!("bytes={}-", existing).parse().unwrap());
                mode = DownloadMode::Resume;
            }
        }

        let response = self
            .client
            .get(file_url(&file.name))
            .headers(headers)
            .send()
            .await?
            .error_for_status()?;

        if matches!(mode, DownloadMode::Resume) && response.status() == reqwest::StatusCode::OK {
            mode = DownloadMode::Fresh;
        }

        let total_size = response.content_length().unwrap_or(0);
        let progress = if self.show_progress {
            let bar = ProgressBar::new(total_size);
            bar.set_style(
                ProgressStyle::with_template(
                    "{spinner:.green} {msg} {bytes}/{total_bytes} {bar:40.cyan/blue} {eta}",
                )
                .unwrap(),
            );
            bar.set_message(file.name.clone());
            Some(bar)
        } else {
            None
        };

        let mut file_handle = open_output(&path, mode).await?;
        let mut stream = response.bytes_stream();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            file_handle.write_all(&chunk).await?;
            if let Some(ref bar) = progress {
                bar.inc(chunk.len() as u64);
            }
        }

        if let Some(bar) = progress {
            bar.finish_and_clear();
        }

        Ok(())
    }

    /// Download all files listed in a manifest.
    pub async fn download_all(&self, manifest: &[ManifestFile]) -> Result<()> {
        std::fs::create_dir_all(&self.root)?;
        for file in manifest {
            self.download_file(file).await?;
        }
        Ok(())
    }

}

fn file_url(name: &str) -> String {
    format!("https://datasets.paradigm.xyz/datasets/ethereum_contracts/{name}")
}

async fn open_output(path: &Path, mode: DownloadMode) -> Result<tokio::fs::File> {
    let mut options = tokio::fs::OpenOptions::new();
    options.create(true);
    match mode {
        DownloadMode::Fresh => {
            options.write(true).truncate(true);
        }
        DownloadMode::Resume => {
            options.write(true).append(true);
        }
    }
    Ok(options.open(path).await?)
}

enum DownloadMode {
    Fresh,
    Resume,
}
