use anyhow::Context;
use cargo_about::{
    licenses::{
        config::{Clarification, ClarificationFile},
        Gatherer, KrateLicense, LicenseFileKind, LicenseInfo, LicenseSource,
    },
    validate_sha256, Krates,
};
use krates::LockOptions;
use serde::{
    de::{Error, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{
    fmt::{Display, Formatter},
    ops::Deref,
    str::FromStr,
    sync::Arc,
};

pub use cargo_about::licenses::{config::Config, LicenseStore};
pub use krates::{Utf8Path, Utf8PathBuf};
pub use spdx::error::ParseError;

#[derive(Clone, Debug)]
pub struct Expression(pub spdx::Expression);

impl Expression {
    pub fn parse(s: &str) -> Result<Expression, ParseError> {
        Ok(Self(spdx::Expression::parse(s)?))
    }
}

impl FromStr for Expression {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Display for Expression {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<spdx::Expression> for Expression {
    fn from(value: spdx::Expression) -> Self {
        Self(value)
    }
}

impl From<&LicenseSource> for Expression {
    fn from(value: &LicenseSource) -> Self {
        match value {
            LicenseSource::Clarified(expr) => Self(expr.clone()),
            // ids come from the spdx license list itself, but may be deprecated
            LicenseSource::Detected(id) => {
                let mode = spdx::ParseMode { allow_deprecated: true, ..spdx::ParseMode::STRICT };
                Self(spdx::Expression::parse_mode(id.name, mode).expect("license id is a valid SPDX expression"))
            },
        }
    }
}

impl Deref for Expression {
    type Target = spdx::Expression;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Expression {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct V;

        impl Visitor<'_> for V {
            type Value = Expression;

            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                write!(formatter, "a valid SPDX license expression")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                match spdx::Expression::parse(v) {
                    Ok(spdx) => Ok(Expression(spdx)),
                    Err(e) => Err(E::custom(e)),
                }
            }
        }

        deserializer.deserialize_str(V)
    }
}

impl Serialize for Expression {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.as_ref())
    }
}

fn deserialize_expression<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Expression>, D::Error> {
    match Option::<Expression>::deserialize(deserializer) {
        Err(_) => Ok(None),
        Ok(opt) => Ok(opt),
    }
}

#[derive(Serialize, Deserialize)]
pub struct LicenseFile {
    /// Filename of the license file
    pub name: String,
    /// If known, the SPDX identifier of the license
    #[serde(default, deserialize_with = "deserialize_expression")]
    pub spdx: Option<Expression>,
    /// The content of the license file
    pub text: String,
}

#[derive(Serialize, Deserialize)]
pub struct Package {
    /// Name of the package
    pub package_name: String,
    /// Version of the package
    pub package_version: String,
    /// Url of the package (this might be the repository or the crates.io page or a homepage)
    pub package_url: Option<String>,
    /// If known, the combined SPDX expression for all licenses of the package (e.g. MIT OR Apache-2.0)
    #[serde(default, deserialize_with = "deserialize_expression")]
    pub license_spdx: Option<Expression>,
    /// All the license files that couldd be found for the package
    pub license_files: Vec<LicenseFile>,
}

/// Create a license store from an internal cache
pub fn license_store_from_cache() -> anyhow::Result<Arc<LicenseStore>> {
    Ok(Arc::new(cargo_about::licenses::store_from_cache()?))
}

/// Retrieve all rust packages and their licenses based on the Cargo.toml at the given path
pub fn get_all_licenses<P: AsRef<Utf8Path>>(
    cargo_toml: P,
    features: Vec<String>,
    license_store: Arc<LicenseStore>,
    config: &Config,
) -> anyhow::Result<Vec<Package>> {
    let krates = cargo_about::get_all_crates(
        cargo_toml.as_ref(),
        false,
        false,
        features,
        false,
        LockOptions { offline: false, frozen: false, locked: true },
        config,
        &[],
    )
    .context("Unable to get crates")?;

    collect_krate_licenses(&krates, license_store, config)
}

/// If the SPDX identifier of individual licenses in the packages are unknown
/// use the license store to analyze the license contents to determine their SPDX.
///
/// This is typically used when the list of packages is generated by a third party tool
/// that has no knowledge of the SPDX identifiers of the individual licenses (e.g. conan).
pub fn augment_licenses(
    licenses: &mut [Package],
    license_store: Arc<LicenseStore>,
    config: &Config,
) -> anyhow::Result<()> {
    for pkg in licenses {
        let clarify = select_clarification(&pkg.package_name, config);

        if let Some(clarify) = clarify {
            if !clarify.git.is_empty() {
                tracing::error!(
                    "Unsupported git clarification for '{} {}', use files clarification instead",
                    pkg.package_name,
                    pkg.package_version
                );
            }

            for invalid_clarification in clarify
                .files
                .iter()
                .filter(|c| !clarification_for_existing_license(c, &pkg.license_files))
            {
                tracing::error!(
                    "Found clarification for file {} that does not exist",
                    invalid_clarification.path,
                );
            }

            pkg.license_spdx = Some(clarify.license.clone().into());

            pkg.license_files.retain_mut(|l| {
                let Some(file_clarify) = select_file_license_clarification(clarify, &l.name) else {
                    // files does not appear in clarification, we can ignore it
                    return false;
                };

                l.spdx = file_clarify.license.clone().map(Into::into);

                if let Err(e) = validate_sha256(&l.text, &file_clarify.checksum) {
                    tracing::error!(
                        "Unable to validate clarification for {} of '{} {}': {}",
                        l.name,
                        pkg.package_name,
                        pkg.package_version,
                        e
                    );
                }

                true
            });
        } else if pkg.license_spdx.is_none() {
            tracing::warn!(
                "No combined license SPDX available for '{} {}'",
                pkg.package_name,
                pkg.package_version
            );
        }

        // use text analysis to try to detect SPDX for licenses with still unspecified SPDX expressions
        for l in pkg.license_files.iter_mut().filter(|l| l.spdx.is_none()) {
            let text = l.text.as_str().into();
            let analysis = license_store.analyze(&text);

            if analysis.score < 0.95 {
                tracing::warn!(
                    "Low confidence of {} for {} on license file SPDX detection for {} of '{} {}'",
                    analysis.score,
                    analysis.name,
                    l.name,
                    pkg.package_name,
                    pkg.package_version
                );
            }

            match Expression::from_str(analysis.name) {
                Ok(file_spdx) => {
                    if pkg
                        .license_spdx
                        .as_ref()
                        .is_some_and(|pkg_spdx| !spdx_any_in_common(pkg_spdx, &file_spdx))
                    {
                        tracing::warn!(
                            "License detection of file {} detected as {} for '{} {}' is probably wrong: package license and file license have nothing in common",
                            l.name,
                            file_spdx,
                            pkg.package_name,
                            pkg.package_version
                        );
                    }

                    l.spdx = Some(file_spdx)
                },
                Err(e) => tracing::error!("License analysis yielded invalid license: {e}"),
            }
        }

        let licenses_in_top_level_expr = licenses_in_expr_opt(pkg.license_spdx.as_ref());
        let licenses_in_files: usize = pkg
            .license_files
            .iter()
            .map(|file| licenses_in_expr_opt(file.spdx.as_ref()))
            .sum();

        if licenses_in_top_level_expr != licenses_in_files {
            tracing::warn!("Mismatch between license SPDX and number of licenses found in files for crate '{} {}'. SPDX specifies {licenses_in_top_level_expr} but found {licenses_in_files} in files",
                pkg.package_name,
                pkg.package_version
            );
        }
    }

    Ok(())
}

fn spdx_any_in_common(expr1: &Expression, expr2: &Expression) -> bool {
    expr1
        .requirements()
        .any(|req1| expr2.requirements().any(|req2| req1 == req2))
}

fn select_clarification<'cfg>(package_name: &str, config: &'cfg Config) -> Option<&'cfg Clarification> {
    config.crates.get(package_name)?.value.clarify.as_ref()
}

fn select_file_license_clarification<'c>(
    clarification: &'c Clarification,
    license_name: &str,
) -> Option<&'c ClarificationFile> {
    clarification.files.iter().find(|f| f.path == license_name)
}

/// Return true iff the given clarification is a clarification for
/// any of the given license files
fn clarification_for_existing_license(file_clarification: &ClarificationFile, licenses: &[LicenseFile]) -> bool {
    licenses.iter().any(|l| {
        file_clarification
            .path
            .file_name()
            .is_some_and(|file_name| file_name == l.name)
    })
}

/// Minimize the license requirements for the packages, based on preferences in the configuration.
/// SPDX identifiers in the configuration are ordered based on preference, starting with the most preferred.
///
/// # Example
/// `MIT OR Apache-2.0` may be minimized to just `MIT`
pub fn minimize_requirements(packages: &mut [Package], config: &Config) -> anyhow::Result<()> {
    for p in packages {
        if let Some(lspdx) = &p.license_spdx {
            let minimized: Vec<_> = lspdx
                .minimized_requirements(&config.accepted)
                .with_context(|| {
                    format!(
                        "Unable to minimize requirements of '{} {}' with {:?}",
                        p.package_name, p.package_version, p.license_spdx
                    )
                })?
                .into_iter()
                .collect();

            // retain the file if any of its SPDX components
            // appear in the minimized version
            p.license_files.retain(|license_file| {
                license_file.spdx.is_none()
                    || license_file.spdx.as_ref().is_some_and(|file_spdx| {
                        file_spdx
                            .requirements()
                            .any(|file_req| minimized.contains(&file_req.req))
                    })
            })
        }
    }

    Ok(())
}

fn collect_krate_licenses(
    krates: &Krates,
    license_store: Arc<LicenseStore>,
    config: &Config,
) -> anyhow::Result<Vec<Package>> {
    let g = Gatherer::with_store(license_store);
    let c = ureq::Agent::new_with_defaults();

    let mut packages = Vec::new();

    for KrateLicense { krate, lic_info, license_files } in g.gather(krates, config, Some(c)) {
        let license = match &lic_info {
            LicenseInfo::Expr(expr) => {
                let licenses_in_top_level_expr = licenses_in_expr(expr);
                let licenses_in_files: usize = license_files
                    .iter()
                    .map(|file| licenses_in_expr(&Expression::from(&file.license)))
                    .sum();

                if licenses_in_top_level_expr != licenses_in_files {
                    tracing::warn!("Mismatch between license SPDX and number of licenses found in files for crate '{krate}'. SPDX specifies {licenses_in_top_level_expr} but found {licenses_in_files} in files");
                }

                Some(expr.clone().into())
            },
            LicenseInfo::Unknown => {
                tracing::warn!("crate '{krate}' has unknown license");
                None
            },
            LicenseInfo::Ignore => {
                // private/proprietary dependency (with publish = false in Cargo.toml)
                continue;
            },
        };

        let mut lfiles = vec![];
        for l in license_files {
            let name = l.path.file_name().unwrap().to_owned();
            let spdx = Some((&l.license).into());

            match l.kind {
                LicenseFileKind::Text(text) | LicenseFileKind::AddendumText(text, _) => {
                    lfiles.push(LicenseFile { name, spdx, text })
                },
                LicenseFileKind::Header => {
                    let license_path = if l.path.is_absolute() {
                        l.path.to_owned()
                    } else {
                        krate.manifest_path.parent().unwrap().join(l.path)
                    };

                    let name = license_path.file_name().unwrap().to_owned();
                    match std::fs::read_to_string(&license_path) {
                        Ok(text) => lfiles.push(LicenseFile { name, spdx, text }),
                        Err(e) => {
                            tracing::warn!("Unable to read license file {license_path}: {e:#}")
                        },
                    }
                },
            }
        }

        if lfiles.is_empty() {
            tracing::warn!("Unable to find any license files for {krate}");
        }

        let package = Package {
            package_name: krate.name.clone(),
            package_version: krate.version.to_string(),
            package_url: krate
                .repository
                .as_ref()
                .or(krate.homepage.as_ref())
                .map(ToOwned::to_owned),
            license_spdx: license,
            license_files: lfiles,
        };

        packages.extend(std::iter::once(package));
    }

    Ok(packages)
}

fn licenses_in_expr(expr: &spdx::Expression) -> usize {
    expr.requirements().count()
}

fn licenses_in_expr_opt(expr: Option<&Expression>) -> usize {
    expr.map(|expr| licenses_in_expr(&expr.0)).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_garbage_spdx() {
        let json = r#"{ "name": "test", "spdx": "garbage", "text": "AAA"  }"#;
        let x: LicenseFile = serde_json::from_str(json).unwrap();
        assert!(x.spdx.is_none());
    }

    #[test]
    fn test_non_garbage_spdx() {
        let json = r#"{ "name": "test", "spdx": "MIT", "text": "AAA"  }"#;
        let x: LicenseFile = serde_json::from_str(json).unwrap();
        assert_eq!(format!("{}", x.spdx.unwrap()), "MIT");
    }

    #[test]
    fn missing_spdx() {
        let json = r#"{ "name": "test", "text": "AAA"  }"#;
        let x: LicenseFile = serde_json::from_str(json).unwrap();
        assert!(x.spdx.is_none());
    }

    #[test]
    fn detect_own_licenses() {
        let manifest = Utf8Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let store = license_store_from_cache().unwrap();
        let packages = get_all_licenses(manifest, vec![], store, &Config::default()).unwrap();

        let anyhow = packages.iter().find(|p| p.package_name == "anyhow").unwrap();
        assert_eq!(anyhow.license_spdx.as_ref().unwrap().to_string(), "MIT OR Apache-2.0");
        assert_eq!(anyhow.license_files.len(), 2);
        assert!(anyhow.license_files.iter().all(|f| f.spdx.is_some() && !f.text.is_empty()));
    }
}
