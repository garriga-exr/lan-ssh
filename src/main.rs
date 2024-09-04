/*
==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--

lan-ssh

Copyright (C) 2023  Anonymous



This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

::--::--::--::--::--::--::--::--::--::--::--::--::--::--::--::--
*/

//! # `lan-ssh`

#![warn(missing_docs)]

// ╔═════════════════╗
// ║   IDENTIFIERS   ║
// ╚═════════════════╝

macro_rules! code_name  { () => { "lan-ssh" }}
macro_rules! version    { () => { "0.3.0" }}

/// # Crate name
pub const NAME: &str = "lan-ssh";

/// # Crate code name
pub const CODE_NAME: &str = code_name!();

/// # ID of this crate
pub const ID: &str = concat!(
    "fcd3df89-ae064a30-c0659bb3-d26985ee-0eeb93ac-117b6582-9d96aa15-0675d68f-",
    "61baac5a-564d3740-89e9779a-0978d086-d9ad5b72-78020b08-cc79622a-f91c0404",
);

/// # Crate version
pub const VERSION: &str = version!();

/// # Crate release date (year/month/day)
pub const RELEASE_DATE: (u16, u8, u8) = (2024, 9, 5);

/// # Tag, which can be used for logging...
pub const TAG: &str = concat!(code_name!(), "::fcd3df89::", version!());

// ╔════════════════════╗
// ║   IMPLEMENTATION   ║
// ╚════════════════════╝

extern crate alloc;

use {
    core::{
        borrow::Borrow,
        iter,
        str::FromStr,
        time::Duration,
    },
    alloc::{
        borrow::Cow,
        collections::BTreeSet,
    },
    std::{
        collections::HashSet,
        env,
        io::{Error, ErrorKind},
        net::{IpAddr, SocketAddr, TcpStream},
        path::PathBuf,
        process::{self, Command},
        sync::mpsc,
    },
    blackhole::{BlackHole, OneTime},
    dia_args::{Answer, Args},
    dia_files::{FilePermissions, Limit, Permissions},
    dia_ip_range::{IPv4Range, IPv4RangeIter},
};

/// # Wrapper for format!(), which prefixes your optional message with: module_path!(), line!()
macro_rules! __ {
    ($($arg: tt)+) => {
        format!("[{module_path}-{line}] {msg}", module_path=module_path!(), line=line!(), msg=format!($($arg)+))
    };
    () => {
        __!("(internal error)")
    };
}

/// # Makes new std::io::Error
macro_rules! err {
    ($kind: path, $($arg: tt)+) => { std::io::Error::new($kind, __!($($arg)+)) };
    ($($arg: tt)+) => { err!(std::io::ErrorKind::Other, $($arg)+) };
    () => { std::io::Error::new(std::io::ErrorKind::Other, __!()) };
}

#[macro_use]
#[allow(unused_macros)]
mod __;
mod ssh;

/// # Result type used in this crate
pub type Result<T> = core::result::Result<T, std::io::Error>;

const TMP_FILE_SUFFIX: &str = concat!(code_name!(), "::", "7ba053cf-15c5c125-5253e386-102baa35");

#[test]
fn test_crate_version() {
    assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
}

const CMD_HELP: &str = "help";
const CMD_HELP_DOCS: Cow<str> = Cow::Borrowed("Prints help and exits.");

const CMD_VERSION: &str = "version";
const CMD_VERSION_DOCS: Cow<str> = Cow::Borrowed("Prints version and exits.");

const CMD_CONNECT: &str = "connect";
const CMD_CONNECT_DOCS: Cow<str> = Cow::Borrowed(concat!(
    "You provide some IP address range(s). The program will search for an active one, then ask you to confirm connection.",
));

const CMD_REMOVE_KNOWN_LAN_HOSTS: &str = "remove-known-lan-hosts";
const CMD_REMOVE_KNOWN_LAN_HOSTS_DOCS: Cow<str> = Cow::Borrowed(concat!(
    "Remove known LAN hosts.\n\n",
    "This command is useful in case you have virtual machines which change IPs regularly...",
));

const OPTION_USER: &[&str] = &["--user"];
const OPTION_USER_DOCS: Cow<str> = Cow::Borrowed("User name.");

const OPTION_STRICT_HOST_KEY_CHECKING: &[&str] = &["--strict-host-key-checking"];
const OPTION_STRICT_HOST_KEY_CHECKING_DOCS: Cow<str> = Cow::Borrowed(concat!(
    "See key 'StrictHostKeyChecking' in ssh_config(5).\n\n",
    "Even if this option is turned off (with `false`), only LAN/private addresses will be allowed.",
));
const OPTION_STRICT_HOST_KEY_CHECKING_DEFAULT: bool = true;

/// # Main
fn main() -> Result<()> {
    if let Err(err) = run() {
        dia_args::lock_write_err(format!("{}\n", err));
        process::exit(1);
    }

    Ok(())
}

/// # Runs the program
fn run() -> Result<()> {
    let args = dia_args::parse()?;
    match args.cmd() {
        Some(CMD_HELP) => {
            ensure_args_are_empty(args.try_into_sub_cmd()?.1)?;
            print_help()
        },
        Some(CMD_VERSION) => {
            ensure_args_are_empty(args.try_into_sub_cmd()?.1)?;
            print_version()
        },
        Some(CMD_CONNECT) => connect(args.try_into_sub_cmd()?.1),
        Some(CMD_REMOVE_KNOWN_LAN_HOSTS) => remove_known_lan_hosts(args.try_into_sub_cmd()?.1),
        Some(other) => Err(Error::new(ErrorKind::InvalidInput, format!("Unknown command: {:?}", other))),
        None => Err(Error::new(ErrorKind::Other, "Missing command")),
    }
}

/// # Ensures arguments are empty
fn ensure_args_are_empty<A>(args: A) -> Result<()> where A: Borrow<Args> {
    let args = args.borrow();
    if args.is_empty() {
        Ok(())
    } else {
        Err(Error::new(ErrorKind::InvalidInput, format!("Unknown arguments: {:?}", args)))
    }
}

/// # Makes version string
fn make_version_string<'a>() -> Cow<'a, str> {
    Cow::Owned(format!(
        "{name} {version} {release_date:?}",
        name=NAME, version=VERSION, release_date=RELEASE_DATE,
    ))
}

/// # Prints version
fn print_version() -> Result<()> {
    dia_args::lock_write_out(format!("{}\n", make_version_string()));
    Ok(())
}

/// # Prints help
fn print_help() -> Result<()> {
    use dia_args::docs::{Cmd, Docs, NO_VALUES, Option};

    let commands = Some(dia_args::make_cmds![
        Cmd::new(CMD_HELP, CMD_HELP_DOCS, None),
        Cmd::new(CMD_VERSION, CMD_VERSION_DOCS, None),
        Cmd::new(CMD_CONNECT, CMD_CONNECT_DOCS, Some(dia_args::make_options![
            Option::new(OPTION_USER, true, NO_VALUES, None, OPTION_USER_DOCS),
            Option::new(
                OPTION_STRICT_HOST_KEY_CHECKING, false, &[], Some(OPTION_STRICT_HOST_KEY_CHECKING_DEFAULT),
                OPTION_STRICT_HOST_KEY_CHECKING_DOCS,
            ),
        ])),
        Cmd::new(CMD_REMOVE_KNOWN_LAN_HOSTS, CMD_REMOVE_KNOWN_LAN_HOSTS_DOCS, None),
    ]);

    let mut docs = Docs::new(make_version_string(), NAME.into());
    docs.commands = commands;
    docs.print()
}

/// # Connects
fn connect(mut args: Args) -> Result<()> {
    let user = args.take::<String>(OPTION_USER)?.ok_or_else(|| Error::new(ErrorKind::InvalidInput, format!("Missing {:?}", OPTION_USER)))?;
    if user.is_empty() || user.chars().any(|c| match c {
        'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => false,
        _ => true,
    }) {
        return Err(Error::new(ErrorKind::InvalidInput, format!("Invalid user name: {:?}", user)));
    }

    let strict_host_key_checking = args.take(OPTION_STRICT_HOST_KEY_CHECKING)?.unwrap_or(OPTION_STRICT_HOST_KEY_CHECKING_DEFAULT);

    let ip_v4_ranges = {
        let data = args.take_args()?;
        match data.len() {
            usize::MIN => return Err(Error::new(ErrorKind::InvalidInput, "Missing IPv4 range(s)")),
            count => data.into_iter().try_fold(HashSet::with_capacity(count), |mut result, next| {
                result.insert(IPv4Range::from_str(&next)?);
                Result::Ok(result)
            })?,
        }
    };

    ensure_args_are_empty(args)?;

    let available_hosts = find_available_hosts(ip_v4_ranges)?;
    let ip = match available_hosts.len() {
        usize::MIN => return Err(err!("Found no available hosts")),
        1 => available_hosts.into_iter().next().ok_or_else(|| err!())?,
        _ => match ask_user_to_pick_a_host(available_hosts)? {
            None => return Ok(()),
            Some(ip) => ip,
        },
    };

    dia_args::lock_write_out(__b!("-> {ip}\n"));

    let mut cmd = Command::new(ssh::APP);
    if strict_host_key_checking == false && (
        ip.is_loopback() || match &ip {
            IpAddr::V4(ip) => ip.is_private(),
            IpAddr::V6(_) => false,
        } || {
            let ip = ip.to_string();
            ["::1", "localhost"].iter().any(|full| &ip == full)
            || ["192.168.", "127.", "fe80:"].iter().any(|prefix| ip.starts_with(prefix))
        }
    ) {
        cmd.args(&["-o", "StrictHostKeyChecking=off"]);
    }
    cmd.arg(format!("{user}@{ip}", user=user, ip=ip));
    match cmd.status() {
        Ok(status) => if status.success() == false {
            match status.code() {
                Some(code) => process::exit(code),
                None => dia_args::lock_write_err(__w!("-> {status}\n", status=status)),
            };
        },
        Err(err) => dia_args::lock_write_err(__w!("Failed to run {cmd:?}: {err}\n", cmd=cmd, err=err)),
    };

    Ok(())
}

fn find_available_hosts<I>(ip_v4_ranges: I) -> Result<BTreeSet<IpAddr>> where I: IntoIterator<Item=IPv4Range> {
    let (sender, receiver) = mpsc::channel();
    let blackhole = BlackHole::make(1024)?;
    let buffer = IPv4RangeIter::new_buffer();
    for ip_v4_range in ip_v4_ranges.into_iter() {
        for ip in IPv4RangeIter::new(ip_v4_range, &buffer) {
            let address = SocketAddr::new(ip.clone(), ssh::DEFAULT_PORT);
            let sender = sender.clone();
            if let Some(job) = blackhole.throw(OneTime::new(move || {
                if TcpStream::connect_timeout(&address, Duration::from_millis(300)).is_ok() {
                    dia_args::lock_write_out(format!("{address}: online\n"));
                    if sender.send(ip).is_err() {
                        // Ignore it
                    }
                } else {
                    dia_args::lock_write_err(__w!("{address}: offline\n"));
                }
            }))? {
                blackhole::run_to_end(job);
            }
        }
    }
    drop(sender);

    let result = receiver.into_iter().collect();
    blackhole.escape_on_idle()?;
    Ok(result)
}

fn ask_user_to_pick_a_host<I>(ips: I) -> Result<Option<IpAddr>> where I: IntoIterator<Item=IpAddr> {
    let ips = ips.into_iter().collect::<Vec<_>>();
    let answers = ips.into_iter().map(|ip| Answer::UserDefined(ip)).chain(iter::once(Answer::Cancel(None))).collect::<Vec<_>>();
    match dia_args::ask_user("Please select a host:", &answers)? {
        Answer::UserDefined(ip) => Ok(Some(*ip)),
        Answer::Cancel(_) => Ok(None),
        _ => Err(err!()),
    }
}

/// # Removes known LAN hosts
fn remove_known_lan_hosts(args: Args) -> Result<()> {
    const HASH: zeros::keccak::Hash = zeros::keccak::Hash::Sha3_512;

    ensure_args_are_empty(args)?;

    let file = PathBuf::from(env::var("HOME").map_err(|e| Error::new(ErrorKind::Other, e))?)
        .join(ssh::HOME_DIR_NAME).join(ssh::KNOWN_HOSTS_FILE_NAME);

    let data = Limit::read_file_to_string(&file, 1024 * 1024 * 9)?;
    let data_hash = HASH.hash(&data);

    let mut new_data = String::with_capacity(data.len());
    let mut reports = String::with_capacity(data.len() / 3);
    for line in data.lines() {
        let line = line.trim();
        if line.starts_with("192.168.") {
            reports.push_str(line.split_whitespace().next().unwrap());
            reports.push('\n');
        } else {
            new_data.push_str(line);
            new_data.push('\n');
        }
    }

    if HASH.hash(&new_data) != data_hash {
        dia_args::lock_write_out(format!("Removed:\n\n{}\n", reports));
        dia_files::write_file(
            file,
            Some(FilePermissions::new(Permissions::ReadWrite, Permissions::None, Permissions::None)),
            new_data,
            TMP_FILE_SUFFIX
        )
    } else {
        dia_args::lock_write_out("Nothing changed\n");
        Ok(())
    }
}
