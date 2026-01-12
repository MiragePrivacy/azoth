use crate::dataset::{DatasetError, Result};
use arrow::array::{Array, ArrayRef, BinaryArray, LargeBinaryArray};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use std::fs::File;
use std::path::Path;

/// Reads contract rows from a parquet file in record batches.
pub struct ParquetContractReader {
    reader: parquet::arrow::arrow_reader::ParquetRecordBatchReader,
}

/// Minimal contract data used for indexing.
#[derive(Debug, Clone)]
pub struct ContractRecord {
    /// Runtime bytecode.
    pub code: Vec<u8>,
    /// Optional keccak hash of runtime bytecode.
    pub code_hash: Option<[u8; 32]>,
}

impl ParquetContractReader {
    /// Open a parquet file for record-batch iteration.
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
        let reader = builder.with_batch_size(8192).build()?;
        Ok(Self { reader })
    }

    /// Return an iterator over contract records.
    pub fn iter(self) -> ParquetContractIter {
        ParquetContractIter::new(self.reader)
    }
}

pub struct ParquetContractIter {
    reader: parquet::arrow::arrow_reader::ParquetRecordBatchReader,
    current_batch: Option<arrow::record_batch::RecordBatch>,
    row_idx: usize,
}

impl ParquetContractIter {
    fn new(reader: parquet::arrow::arrow_reader::ParquetRecordBatchReader) -> Self {
        Self {
            reader,
            current_batch: None,
            row_idx: 0,
        }
    }

    fn next_batch(&mut self) -> Result<bool> {
        let batch = match self.reader.next() {
            Some(Ok(batch)) => batch,
            Some(Err(err)) => return Err(DatasetError::from(err)),
            None => return Ok(false),
        };
        self.current_batch = Some(batch);
        self.row_idx = 0;
        Ok(true)
    }
}

impl Iterator for ParquetContractIter {
    type Item = Result<ContractRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let batch = match self.current_batch.as_ref() {
                Some(batch) => batch,
                None => {
                    if let Err(err) = self.next_batch() {
                        return Some(Err(err));
                    }
                    self.current_batch.as_ref()?
                }
            };

            if self.row_idx >= batch.num_rows() {
                self.current_batch = None;
                continue;
            }

            let row = self.row_idx;
            self.row_idx += 1;

            let code_col = batch.column_by_name("code");
            let hash_col = batch.column_by_name("code_hash");
            if code_col.is_none() {
                return Some(Err(DatasetError::Format(
                    "missing `code` column".to_string(),
                )));
            }

            let code = match read_binary(code_col.unwrap(), row) {
                Some(bytes) => bytes.to_vec(),
                None => return Some(Err(DatasetError::Format("null code".to_string()))),
            };

            let code_hash = hash_col
                .and_then(|col| read_binary(col, row))
                .and_then(|bytes| {
                    if bytes.len() == 32 {
                        let mut out = [0u8; 32];
                        out.copy_from_slice(bytes);
                        Some(out)
                    } else {
                        None
                    }
                });

            return Some(Ok(ContractRecord { code, code_hash }));
        }
    }
}

fn read_binary(array: &ArrayRef, row: usize) -> Option<&[u8]> {
    if let Some(binary) = array.as_any().downcast_ref::<BinaryArray>() {
        if binary.is_null(row) {
            None
        } else {
            Some(binary.value(row))
        }
    } else if let Some(binary) = array.as_any().downcast_ref::<LargeBinaryArray>() {
        if binary.is_null(row) {
            None
        } else {
            Some(binary.value(row))
        }
    } else {
        None
    }
}
