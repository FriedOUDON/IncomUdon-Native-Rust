use std::{
    fs, io,
    path::{Path, PathBuf},
};

use directories::ProjectDirs;
use incomudon_core::{ProfileError, ProfileStore};
use thiserror::Error;

const PROFILE_FILE_NAME: &str = "profiles.json";

#[derive(Debug, Error)]
pub enum ProfileStorageError {
    #[error("no platform configuration directory is available")]
    ConfigDirectoryUnavailable,
    #[error("failed to read profile store from {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to decode profile store from {path}: {source}")]
    Decode {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("profile store from {path} is invalid: {source}")]
    Invalid {
        path: PathBuf,
        #[source]
        source: ProfileError,
    },
    #[error("failed to create profile directory {path}: {source}")]
    CreateDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to serialize profile store: {0}")]
    Encode(#[from] serde_json::Error),
    #[error("failed to write profile store to {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

pub fn default_profile_path() -> Result<PathBuf, ProfileStorageError> {
    let project_dirs = ProjectDirs::from("net", "FriedOUDON", "IncomUdon")
        .ok_or(ProfileStorageError::ConfigDirectoryUnavailable)?;
    Ok(project_dirs.config_dir().join(PROFILE_FILE_NAME))
}

pub fn load_from_path(path: &Path) -> Result<ProfileStore, ProfileStorageError> {
    let contents = fs::read_to_string(path).map_err(|source| ProfileStorageError::Read {
        path: path.to_owned(),
        source,
    })?;
    let store: ProfileStore =
        serde_json::from_str(&contents).map_err(|source| ProfileStorageError::Decode {
            path: path.to_owned(),
            source,
        })?;
    store
        .validate()
        .map_err(|source| ProfileStorageError::Invalid {
            path: path.to_owned(),
            source,
        })?;
    Ok(store)
}

pub fn save_to_path(path: &Path, store: &ProfileStore) -> Result<(), ProfileStorageError> {
    store
        .validate()
        .map_err(|source| ProfileStorageError::Invalid {
            path: path.to_owned(),
            source,
        })?;
    let parent = path
        .parent()
        .ok_or(ProfileStorageError::ConfigDirectoryUnavailable)?;
    fs::create_dir_all(parent).map_err(|source| ProfileStorageError::CreateDirectory {
        path: parent.to_owned(),
        source,
    })?;
    let encoded = serde_json::to_vec_pretty(store)?;
    fs::write(path, encoded).map_err(|source| ProfileStorageError::Write {
        path: path.to_owned(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saves_and_loads_a_valid_profile_store() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(PROFILE_FILE_NAME);
        let store = ProfileStore::default();

        save_to_path(&path, &store).unwrap();
        assert_eq!(load_from_path(&path).unwrap(), store);
    }
}
