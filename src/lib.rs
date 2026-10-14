use cargo_about::{
    licenses::{
        config::{Clarification, ClarificationFile},
        Gatherer, KrateLicense, LicenseFileKind, LicenseInfo, LicenseSource,
    },
    validate_sha256, Krates,
};
use krates::LockOptions;
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};
use std::{
    fmt::{Display, Formatter},
    ops::Deref,
    str::FromStr,
    sync::Arc,
};

pub use cargo_about::licenses::{config::Config, LicenseStore};
pub use krates::{Utf8Path, Utf8PathBuf};
pub use spdx::{error::ParseError, expression::MinimizeError};

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
                let mode = spdx::ParseMode {
                    allow_deprecated: true,
                    ..spdx::ParseMode::STRICT
                };
                Self(
                    spdx::Expression::parse_mode(id.name, mode)
                        .expect("license id is a valid SPDX expression"),
                )
            }
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
                E: serde::de::Error,
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

fn deserialize_expression<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Expression>, D::Error> {
    match Option::<Expression>::deserialize(deserializer) {
        Err(_) => Ok(None),
        Ok(opt) => Ok(opt),
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LicenseFile {
    /// Filename of the license file
    pub name: String,
    /// If known, the SPDX identifier of the license
    #[serde(default, deserialize_with = "deserialize_expression")]
    pub spdx: Option<Expression>,
    /// The content of the license file
    pub text: String,
}

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Clone, Debug)]
pub struct PackageIdentification {
    pub name: String,
    pub version: String,
}

impl Display for PackageIdentification {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.name, self.version)
    }
}

impl From<&Package> for PackageIdentification {
    fn from(pkg: &Package) -> Self {
        Self {
            name: pkg.package_name.clone(),
            version: pkg.package_version.clone(),
        }
    }
}

/// A single non-fatal finding
#[derive(Debug, thiserror::Error)]
pub enum Diagnostic {
    #[error("Unsupported git clarification for '{package}', use files clarification instead")]
    GitClarification { package: PackageIdentification },
    #[error("Found clarification for file {path} that does not exist")]
    ClarificationWithoutFile { path: Utf8PathBuf },
    #[error("Unable to validate clarification for {file} of '{package}'")]
    ChecksumMismatch {
        package: PackageIdentification,
        file: String,
        #[source]
        source: anyhow::Error,
    },
    #[error("No combined license SPDX available for '{package}'")]
    MissingLicenseSpdx { package: PackageIdentification },
    #[error("Low confidence of {score} for {spdx} on license file SPDX detection for {file} of '{package}'")]
    LowConfidence {
        package: PackageIdentification,
        file: String,
        spdx: String,
        score: f32,
    },
    #[error("License detection of file {file} detected as {spdx} for '{package}' is probably wrong: package license and file license have nothing in common")]
    UnrelatedFileLicense {
        package: PackageIdentification,
        file: String,
        spdx: Box<Expression>,
    },
    #[error("License analysis yielded invalid license")]
    InvalidLicense(#[source] ParseError),
    #[error("Unable to read license file {path}")]
    UnreadableLicenseFile {
        path: Utf8PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("Unable to find any license files for '{package}'")]
    NoLicenseFiles { package: PackageIdentification },
    #[error("Mismatch between license SPDX and number of licenses found in files for crate '{package}'. SPDX specifies {expected} but found {found} in files")]
    LicenseCountMismatch {
        package: PackageIdentification,
        expected: usize,
        found: usize,
    },
    #[error("Unable to minimize requirements of '{package}'")]
    Minimize {
        package: PackageIdentification,
        #[source]
        source: MinimizeError,
    },
}

/// All diagnostics found by an operation that ran to completion anyway
#[derive(Debug)]
pub struct Incomplete {
    /// The packages, processed as far as possible despite the diagnostics
    pub partially_processed: Vec<Package>,
    pub diagnostics: Vec<Diagnostic>,
}

impl Display for Incomplete {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for (i, e) in self.diagnostics.iter().enumerate() {
            if i > 0 {
                f.write_str("\n")?;
            }
            // reuse the formatter so `{:#}` reaches the inner errors
            Display::fmt(e, f)?;
        }
        Ok(())
    }
}

impl std::error::Error for Incomplete {}

fn finish(packages: Vec<Package>, diagnostics: Vec<Diagnostic>) -> Result<Vec<Package>, Error> {
    if diagnostics.is_empty() {
        Ok(packages)
    } else {
        Err(Incomplete {
            partially_processed: packages,
            diagnostics,
        }
        .into())
    }
}

/// Failure of any operation of this crate
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Unable to load license store")]
    LicenseStore(#[source] anyhow::Error),
    #[error("Unable to get crates")]
    Krates(#[source] anyhow::Error),
    #[error(transparent)]
    Incomplete(#[from] Incomplete),
}

/// Create a license store from an internal cache
pub fn license_store_from_cache() -> Result<Arc<LicenseStore>, Error> {
    cargo_about::licenses::store_from_cache()
        .map(Arc::new)
        .map_err(Error::LicenseStore)
}

/// Retrieve all rust packages and their licenses based on the Cargo.toml at the given path.
///
/// Diagnostics for individual packages do not abort the collection but yield [`Error::Incomplete`].
pub fn get_all_licenses<P: AsRef<Utf8Path>>(
    cargo_toml: P,
    features: Vec<String>,
    license_store: Arc<LicenseStore>,
    config: &Config,
) -> Result<Vec<Package>, Error> {
    let krates = cargo_about::get_all_crates(
        cargo_toml.as_ref(),
        false,
        false,
        features,
        false,
        LockOptions {
            offline: false,
            frozen: false,
            locked: true,
        },
        config,
        &[],
    )
    .map_err(Error::Krates)?;

    collect_krate_licenses(&krates, license_store, config)
}

/// If the SPDX identifier of individual licenses in the packages are unknown
/// use the license store to analyze the license contents to determine their SPDX.
///
/// This is typically used when the list of packages is generated by a third party tool
/// that has no knowledge of the SPDX identifiers of the individual licenses (e.g. conan).
///
/// All diagnostics are collected before failing, so every one of them is reported at once.
/// On failure the partially augmented packages are handed back inside the error.
pub fn augment_licenses(
    mut licenses: Vec<Package>,
    license_store: Arc<LicenseStore>,
    config: &Config,
) -> Result<Vec<Package>, Error> {
    let mut diagnostics = vec![];

    for pkg in &mut licenses {
        let clarify = select_clarification(&pkg.package_name, config);
        let package = PackageIdentification::from(&*pkg);

        if let Some(clarify) = clarify {
            if !clarify.git.is_empty() {
                diagnostics.push(Diagnostic::GitClarification {
                    package: package.clone(),
                });
            }

            for invalid_clarification in clarify
                .files
                .iter()
                .filter(|c| !clarification_for_existing_license(c, &pkg.license_files))
            {
                diagnostics.push(Diagnostic::ClarificationWithoutFile {
                    path: invalid_clarification.path.clone(),
                });
            }

            pkg.license_spdx = Some(clarify.license.clone().into());

            pkg.license_files.retain_mut(|l| {
                let Some(file_clarify) = select_file_license_clarification(clarify, &l.name) else {
                    // files does not appear in clarification, we can ignore it
                    return false;
                };

                l.spdx = file_clarify.license.clone().map(Into::into);

                if let Err(source) = validate_sha256(&l.text, &file_clarify.checksum) {
                    diagnostics.push(Diagnostic::ChecksumMismatch {
                        package: package.clone(),
                        file: l.name.clone(),
                        source,
                    });
                }

                true
            });
        } else if pkg.license_spdx.is_none() {
            diagnostics.push(Diagnostic::MissingLicenseSpdx {
                package: package.clone(),
            });
        }

        // use text analysis to try to detect SPDX for licenses with still unspecified SPDX expressions
        for l in pkg.license_files.iter_mut().filter(|l| l.spdx.is_none()) {
            let text = l.text.as_str().into();
            let analysis = license_store.analyze(&text);

            if analysis.score < 0.95 {
                diagnostics.push(Diagnostic::LowConfidence {
                    package: package.clone(),
                    file: l.name.clone(),
                    spdx: analysis.name.to_owned(),
                    score: analysis.score,
                });
            }

            match Expression::from_str(analysis.name) {
                Ok(file_spdx) => {
                    if pkg
                        .license_spdx
                        .as_ref()
                        .is_some_and(|pkg_spdx| !spdx_any_in_common(pkg_spdx, &file_spdx))
                    {
                        diagnostics.push(Diagnostic::UnrelatedFileLicense {
                            package: package.clone(),
                            file: l.name.clone(),
                            spdx: Box::new(file_spdx.clone()),
                        });
                    }

                    l.spdx = Some(file_spdx)
                }
                Err(e) => diagnostics.push(Diagnostic::InvalidLicense(e)),
            }
        }

        let licenses_in_top_level_expr = licenses_in_expr_opt(pkg.license_spdx.as_ref());
        let licenses_in_files: usize = pkg
            .license_files
            .iter()
            .map(|file| licenses_in_expr_opt(file.spdx.as_ref()))
            .sum();

        if licenses_in_top_level_expr != licenses_in_files {
            diagnostics.push(Diagnostic::LicenseCountMismatch {
                package: package.clone(),
                expected: licenses_in_top_level_expr,
                found: licenses_in_files,
            });
        }
    }

    finish(licenses, diagnostics)
}

fn spdx_any_in_common(expr1: &Expression, expr2: &Expression) -> bool {
    expr1
        .requirements()
        .any(|req1| expr2.requirements().any(|req2| req1 == req2))
}

fn select_clarification<'cfg>(
    package_name: &str,
    config: &'cfg Config,
) -> Option<&'cfg Clarification> {
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
fn clarification_for_existing_license(
    file_clarification: &ClarificationFile,
    licenses: &[LicenseFile],
) -> bool {
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
///
/// Packages that cannot be minimized are left untouched and reported via [`Error::Incomplete`].
pub fn minimize_requirements(
    mut packages: Vec<Package>,
    config: &Config,
) -> Result<Vec<Package>, Error> {
    let mut diagnostics = vec![];

    for p in &mut packages {
        let Some(lspdx) = &p.license_spdx else {
            continue;
        };

        let minimized = match lspdx.minimized_requirements(&config.accepted) {
            Ok(minimized) => minimized,
            Err(source) => {
                diagnostics.push(Diagnostic::Minimize {
                    package: (&*p).into(),
                    source,
                });
                continue;
            }
        };

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

    finish(packages, diagnostics)
}

/// Allow a partial function result, turning it into Ok(_)
pub fn allow_incomplete(result: Result<Vec<Package>, Error>) -> Result<Vec<Package>, Error> {
    match result {
        Ok(packages) => Ok(packages),
        Err(Error::Incomplete(incomplete)) => {
            for diagnostic in incomplete.diagnostics {
                tracing::warn!("{diagnostic}");
            }
            Ok(incomplete.partially_processed)
        }
        Err(e) => Err(e),
    }
}

fn collect_krate_licenses(
    krates: &Krates,
    license_store: Arc<LicenseStore>,
    config: &Config,
) -> Result<Vec<Package>, Error> {
    let g = Gatherer::with_store(license_store);
    let c = ureq::Agent::new_with_defaults();

    let mut packages = Vec::new();
    let mut diagnostics = Vec::new();

    for KrateLicense {
        krate,
        lic_info,
        license_files,
    } in g.gather(krates, config, Some(c))
    {
        let package = PackageIdentification {
            name: krate.name.clone(),
            version: krate.version.to_string(),
        };

        let license = match &lic_info {
            LicenseInfo::Expr(expr) => {
                let licenses_in_top_level_expr = licenses_in_expr(expr);
                let licenses_in_files: usize = license_files
                    .iter()
                    .map(|file| licenses_in_expr(&Expression::from(&file.license)))
                    .sum();

                if licenses_in_top_level_expr != licenses_in_files {
                    diagnostics.push(Diagnostic::LicenseCountMismatch {
                        package: package.clone(),
                        expected: licenses_in_top_level_expr,
                        found: licenses_in_files,
                    });
                }

                Some(expr.clone().into())
            }
            LicenseInfo::Unknown => {
                diagnostics.push(Diagnostic::MissingLicenseSpdx {
                    package: package.clone(),
                });
                None
            }
            LicenseInfo::Ignore => {
                // private/proprietary dependency (with publish = false in Cargo.toml)
                continue;
            }
        };

        let mut lfiles = vec![];
        for l in license_files {
            let name = l.path.file_name().unwrap().to_owned();
            let spdx = Some((&l.license).into());

            match l.kind {
                LicenseFileKind::Text(text) | LicenseFileKind::AddendumText(text, _) => {
                    lfiles.push(LicenseFile { name, spdx, text })
                }
                LicenseFileKind::Header => {
                    let license_path = if l.path.is_absolute() {
                        l.path.to_owned()
                    } else {
                        krate.manifest_path.parent().unwrap().join(l.path)
                    };

                    let name = license_path.file_name().unwrap().to_owned();
                    match std::fs::read_to_string(&license_path) {
                        Ok(text) => lfiles.push(LicenseFile { name, spdx, text }),
                        Err(source) => diagnostics.push(Diagnostic::UnreadableLicenseFile {
                            path: license_path,
                            source,
                        }),
                    }
                }
            }
        }

        if lfiles.is_empty() {
            diagnostics.push(Diagnostic::NoLicenseFiles {
                package: package.clone(),
            });
        }

        let package = Package {
            package_name: package.name,
            package_version: package.version,
            package_url: krate
                .repository
                .as_ref()
                .or(krate.homepage.as_ref())
                .map(ToOwned::to_owned),
            license_spdx: license,
            license_files: lfiles,
        };

        packages.push(package);
    }

    finish(packages, diagnostics)
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
        // some dependencies ship incomplete license files, that is fine here
        let packages = match get_all_licenses(manifest, vec![], store, &Config::default()) {
            Ok(packages)
            | Err(Error::Incomplete(Incomplete {
                partially_processed: packages,
                ..
            })) => packages,
            Err(e) => panic!("{e:#}"),
        };

        let anyhow = packages
            .iter()
            .find(|p| p.package_name == "anyhow")
            .unwrap();
        assert_eq!(
            anyhow.license_spdx.as_ref().unwrap().to_string(),
            "MIT OR Apache-2.0"
        );
        assert_eq!(anyhow.license_files.len(), 2);
        assert!(anyhow
            .license_files
            .iter()
            .all(|f| f.spdx.is_some() && !f.text.is_empty()));
    }
}
