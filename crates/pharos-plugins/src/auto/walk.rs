use super::*;
use std::{io::BufReader, path::Path};

impl Shared {
    pub(super) fn scan(&self) {
        let _gate = self.scan_gate.lock().unwrap();
        let old = self.zones.load_full();
        let mut zones = HashMap::new();
        let mut seen = HashMap::new();
        let root =
            std::fs::canonicalize(&self.directory).unwrap_or_else(|_| self.directory.clone());
        visit(&root, &mut |path| {
            let Some(filename) = path.file_name().and_then(|name| name.to_str()) else {
                return;
            };
            let Some(captures) = self.regex.captures(filename) else {
                return;
            };
            let mut origin = String::new();
            captures.expand(&self.template, &mut origin);
            if origin.is_empty() {
                return;
            }
            if !origin.ends_with('.') {
                origin.push('.');
            }
            if let Some(previous) = seen.get(&origin) {
                pharos_server::logging::log(
                    "WARN",
                    "auto",
                    &format!(
                        "Multiple zone files match origin {origin:?}: using {previous:?} instead of {path:?}"
                    ),
                );
                return;
            }
            seen.insert(origin.clone(), path.to_owned());
            let Ok(apex) = origin.parse::<Name>() else {
                return;
            };
            if let Some(entry) = old.origins.get(&origin) {
                *entry.path.lock().unwrap() = path.to_owned();
                zones.insert(origin, Arc::clone(entry));
            } else {
                let result = std::fs::File::open(path)
                    .map_err(|error| error.to_string())
                    .and_then(|file| {
                        Zone::load_reader_with_serial(
                            apex.clone(),
                            path,
                            BufReader::new(file),
                            Some(0),
                        )
                    });
                match result {
                    Ok(zone) => {
                        pharos_server::logging::log(
                            "INFO",
                            "auto",
                            &format!("Inserting Zone {origin} from {}", path.display()),
                        );
                        let case_mismatch = origin.bytes().any(|byte| byte.is_ascii_uppercase());
                        zones.insert(
                            origin.clone(),
                            Arc::new(Entry {
                                origin,
                                case_mismatch,
                                apex,
                                path: Mutex::new(path.to_owned()),
                                current: ZoneHolder::from(Some(Arc::new(zone))),
                                task: Mutex::new(None),
                            }),
                        );
                    }
                    Err(error) => pharos_server::logging::log(
                        "WARN",
                        "auto",
                        &format!("Cannot load Zone {origin} from {}: {error}", path.display()),
                    ),
                }
            }
        });
        for entry in old
            .origins
            .values()
            .filter(|entry| !zones.contains_key(&entry.origin))
        {
            pharos_server::logging::log("INFO", "auto", &format!("Deleting Zone {}", entry.origin));
            if let Some(task) = entry.task.lock().unwrap().take() {
                task.abort();
            }
        }
        let mut canonical = HashMap::new();
        let mut entries: Vec<_> = zones.values().collect();
        entries.sort_by(|a, b| a.path.lock().unwrap().cmp(&b.path.lock().unwrap()));
        for entry in entries {
            let mut key = entry.apex.as_wire().to_vec();
            key.make_ascii_lowercase();
            canonical.entry(key).or_insert_with(|| Arc::clone(entry));
        }
        #[cfg(feature = "plugin-prometheus")]
        self.metrics
            .publish(zones.values().map(|entry| entry.apex.clone()).collect());
        self.zones.store(Arc::new(Zones {
            origins: zones,
            canonical,
        }));
    }
}

impl Entry {
    pub(super) fn reload(&self) -> bool {
        let path = self.path.lock().unwrap();
        let file = match std::fs::File::open(&*path) {
            Ok(file) => file,
            Err(error) => {
                pharos_server::logging::log(
                    "WARN",
                    "auto",
                    &format!("Cannot open {}: {error}", path.display()),
                );
                return false;
            }
        };
        // RFC 1035 §3.3.13: the SOA serial identifies the Zone version.
        let serial = self.current.load().as_ref().and_then(|zone| zone.serial());
        match Zone::load_reader_with_serial(self.apex.clone(), &path, BufReader::new(file), serial)
        {
            Ok(zone) => {
                self.current.store(Some(Arc::new(zone)));
                true
            }
            Err(error) => {
                if error == "no change in SOA serial" {
                    return false;
                }
                pharos_server::logging::log(
                    "WARN",
                    "auto",
                    &format!(
                        "Cannot reload Zone {} from {}: {error}",
                        self.apex,
                        path.display()
                    ),
                );
                false
            }
        }
    }
}

fn visit(path: &Path, callback: &mut impl FnMut(&Path)) {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            pharos_server::logging::log(
                "WARN",
                "auto",
                &format!("Cannot read {}: {error}", path.display()),
            );
            return;
        }
    };
    if metadata.is_dir() {
        let entries = match std::fs::read_dir(path) {
            Ok(entries) => entries,
            Err(error) => {
                pharos_server::logging::log(
                    "WARN",
                    "auto",
                    &format!("Cannot read directory {}: {error}", path.display()),
                );
                return;
            }
        };
        let mut paths: Vec<_> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect();
        paths.sort();
        for path in paths {
            visit(&path, callback);
        }
    } else {
        callback(path);
    }
}
