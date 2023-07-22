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
        short = 'k',
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
        requires = "base"
    )]
    pub ca_cert: Option<String>,

    #[clap(
        short,
        long,
        action,
        help_heading = "Chameleon Certificate Generation",
        requires = "base"
    )]
    pub delta: Option<String>,

    /// Full path and filename of file to receive freshly generated base certificate containing a
    /// deltaCertificateDescriptor extension
    #[clap(
        short,
        long,
        action,
        help_heading = "Chameleon Certificate Generation",
        conflicts_with = "request",
        conflicts_with = "check",
        requires = "delta",
        requires = "ca_cert",
        requires = "ca_key"
    )]
    pub base: Option<String>,

    /// Full path and filename of file containing certificate that serves as a template for CSR
    /// generation (only the public key will be changed)
    #[clap(
        short,
        long,
        action,
        help_heading = "Chameleon Certificate Signing Request Generation"
    )]
    pub template_cert: Option<String>,

    /// Full path and filename of file to receive freshly generated certificate signing request
    /// containing deltaCertificateRequest attribute
    #[clap(
        short = 'q',
        long,
        action,
        help_heading = "Chameleon Certificate Signing Request Generation",
        requires = "template_cert",
        conflicts_with = "base",
        conflicts_with = "check"
    )]
    pub request: Option<String>,

    /// Full path and filename of certificate that should match the certificate rehydrated from the
    /// check certificate
    #[clap(
        short,
        long,
        action,
        help_heading = "Chameleon Certificate Extension Check",
        requires = "check"
    )]
    pub reference: Option<String>,

    /// Full path and filename of file to receive freshly generated base certificate containing a
    /// deltaCertificateDescriptor extension
    #[clap(
        short = 'v',
        long,
        action,
        help_heading = "Chameleon Certificate Extension Check",
        requires = "reference",
        conflicts_with = "base",
        conflicts_with = "request"
    )]
    pub check: Option<String>,
}
