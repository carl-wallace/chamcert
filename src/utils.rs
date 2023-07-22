//! Utility functions used by the pbyk utility

use std::fs::File;
use std::io::Read;
use std::path::Path;
use crate::args::ChamCertArgs;
use log::LevelFilter;
use log4rs::{
    append::console::ConsoleAppender,
    config::{Appender, Config, Root},
    encode::pattern::PatternEncoder,
};
use crate::Error;

/// Configures logging per logging-related elements of the provided [PbYkArgs] instance
pub(crate) fn configure_logging(args: &ChamCertArgs) {
    let mut logging_configured = false;

    if let Some(logging_config) = &args.logging_config {
        if let Err(e) = log4rs::init_file(logging_config, Default::default()) {
            println!(
                "ERROR: failed to configure logging using {} with {:?}. Continuing without logging.",
                logging_config, e
            );
        } else {
            logging_configured = true;
        }
    }

    if !logging_configured && args.log_to_console {
        // if there's no config, prepare one using stdout
        let stdout = ConsoleAppender::builder()
            .encoder(Box::new(PatternEncoder::new("{m}{n}")))
            .build();
        match Config::builder()
            .appender(Appender::builder().build("stdout", Box::new(stdout)))
            .build(Root::builder().appender("stdout").build(LevelFilter::Info))
        {
            Ok(config) => {
                let handle = log4rs::init_config(config);
                if let Err(e) = handle {
                    println!(
                        "ERROR: failed to configure logging for stdout with {:?}. Continuing without logging.",
                        e
                    );
                }
            }
            Err(e) => {
                println!("ERROR: failed to prepare default logging configuration with {:?}. Continuing without logging", e);
            }
        }
    }
}

/// `get_file_as_byte_vec` provides support for reading artifacts from file when PITTv3 is built using
/// the `std_app` feature.
pub fn get_file_as_byte_vec(filename: &Path) -> crate::Result<Vec<u8>> {
    match File::open(filename) {
        Ok(mut f) => match std::fs::metadata(filename) {
            Ok(metadata) => {
                let mut buffer = vec![0; metadata.len() as usize];
                match f.read_exact(&mut buffer) {
                    Ok(_) => Ok(buffer),
                    Err(_e) => Err(Error::Unrecognized),
                }
            }
            Err(_e) => Err(Error::Unrecognized),
        },
        Err(_e) => Err(Error::Unrecognized),
    }
}