use clap::Parser;

#[derive(Parser, Debug)]
#[command(arg_required_else_help(true))]
#[command(author, version, about = "", long_about = "")]
pub struct ChamCertArgs {
    /// Full path and filename of YAML-formatted configuration file for log4rs logging mechanism.
    /// See <https://docs.rs/log4rs/latest/log4rs/> for details.
    #[clap(
    short,
    long,
    action,
    help_heading = "Logging",
    conflicts_with = "log_to_console"
    )]
    pub logging_config: Option<String>,

    /// Log output to the console (in addition to any destinations specified by logging_config)
    #[clap(
    long,
    short = 'x',
    action,
    help_heading = "Logging",
    conflicts_with = "logging_config"
    )]
    pub log_to_console: bool,

    /// Full path and filename of private key to use when signing the base.
    #[clap(
    short='k',
    long,
    action,
    help_heading = "Chameleon Certificate Generation",
    requires = "base"
    )]
    pub ca_key: Option<String>,

    /// Full path and filename of CA certificate corresponding to ca_key (contributes name to base).
    #[clap(
    short,
    long,
    action,
    help_heading = "Chameleon Certificate Generation",
    requires = "base",
    )]
    pub ca_cert: Option<String>,

    #[clap(
    short,
    long,
    action,
    help_heading = "Chameleon Certificate Generation",
    requires = "base",
    )]
    pub delta: Option<String>,

    /// Full path and filename of file to receive freshly generated base certificate containing a
    /// deltaCertificateDescriptor extension
    #[clap(
    short,
    long,
    action,
    help_heading = "Chameleon Certificate Generation",
    conflicts_with = "csr",
    requires = "delta",
    requires = "ca_cert",
    requires = "ca_key",
    )]
    pub base: Option<String>,

    /// Full path and filename of file to receive freshly generated CSR containing deltaCertificateRequest
    /// attribute
    #[clap(
    short='r',
    long,
    action,
    help_heading = "Chameleon CSR Generation",
    conflicts_with = "base",
    conflicts_with = "delta",
    conflicts_with = "ca_cert",
    conflicts_with = "ca_key",
    )]
    pub csr: Option<String>,

    /// Full path and filename of file containing certificate that serves as a template for CSR
    /// generation (only the public key will be changed)
    #[clap(
    short,
    long,
    action,
    help_heading = "Chameleon CSR Generation",
    conflicts_with = "base",
    conflicts_with = "delta",
    conflicts_with = "ca_cert",
    conflicts_with = "ca_key",
    )]
    pub template_cert: Option<String>,
}