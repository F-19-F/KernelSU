use anyhow::{Ok, Result};
use clap::Parser;
#[cfg(target_os="android")]
use android_logger::Config;
use log::LevelFilter;

use crate::{apk_sign, debug, event, module};

/// KernelSU userspace cli
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Start KernelSU userspace daemon
    Daemon,

    /// Manage KernelSU modules
    Module {
        #[command(subcommand)]
        command: Module,
    },

    /// Trigger `post-fs-data` event
    PostFsData,

    /// Trigger `service` event
    Services,

    /// Trigger `boot-complete` event
    BootCompleted,

    /// Install KernelSU userspace component to system
    Install,

    /// SELinux policy Patch tool
    Sepolicy {
        #[command(subcommand)]
        command: Sepolicy,
    },

    /// For developers
    Debug {
        #[command(subcommand)]
        command: Debug,
    },
}
#[derive(clap::Subcommand, Debug)]
enum Debug {
    /// Set the manager app, kernel CONFIG_KSU_DEBUG should be enabled.
    SetManager {
        /// manager package name
        #[arg(default_value_t = String::from("me.weishu.kernelsu"))]
        apk: String,
    },

    /// Get apk size and hash
    GetSign {
        /// apk path
        apk: String,
    },

    /// Root Shell
    Su,

    /// Get kernel version
    Version,

    /// For testing
    Test,
}

#[derive(clap::Subcommand, Debug)]
enum Sepolicy {
    /// Patch sepolicy
    Patch {
        /// sepolicy statements
        sepolicy: String,
    },

    /// Apply sepolicy from file
    Apply {
        /// sepolicy file path
        file: String,
    },
}

#[derive(clap::Subcommand, Debug)]
enum Module {
    /// Install module <ZIP>
    Install {
        /// module zip file path
        zip: String,
    },

    /// Uninstall module <id>
    Uninstall {
        /// module id
        id: String,
    },

    /// enable module <id>
    Enable {
        /// module id
        id: String,
    },

    /// disable module <id>
    Disable {
        // module id
        id: String,
    },

    /// list all modules
    List,
}

pub fn run() -> Result<()> {
    #[cfg(target_os="android")]
    android_logger::init_once(
        Config::default()
            .with_max_level(LevelFilter::Trace) // limit log level
            .with_tag("KernelSU") // logs will show under mytag tag
    );

    #[cfg(not(target_os="android"))]
    env_logger::init();

    let cli = Args::parse();

    log::info!("command: {:?}", cli.command);

    let result = match cli.command {
        Commands::Daemon => event::daemon(),
        Commands::PostFsData => event::on_post_data_fs(),
        Commands::BootCompleted => event::on_boot_completed(),

        Commands::Module { command } => {

            match command {
                Module::Install { zip } => module::install_module(zip),
                Module::Uninstall { id } => module::uninstall_module(id),
                Module::Enable { id } => module::enable_module(id),
                Module::Disable { id } => module::disable_module(id),
                Module::List => module::list_modules(),
            }
        }
        Commands::Install => event::install(),
        Commands::Sepolicy { command } => match command {
            Sepolicy::Patch { sepolicy } => crate::sepolicy::live_patch(&sepolicy),
            Sepolicy::Apply { file } => crate::sepolicy::apply_file(file),
        },
        Commands::Services => event::on_services(),

        Commands::Debug { command } => match command {
            Debug::SetManager { apk } => debug::set_manager(&apk),
            Debug::GetSign { apk } => {
                let sign = apk_sign::get_apk_signature(&apk)?;
                println!("size: {:#x}, hash: {:#x}", sign.0, sign.1);
                Ok(())
            }
            Debug::Version => {
                println!("Kernel Version: {}", crate::ksu::get_version());
                Ok(())
            }
            Debug::Su => crate::ksu::grant_root(),
            Debug::Test => todo!()
        },
    };

    if let Err(e) = &result {
        log::error!("Error: {}", e);
    }
    result
}
