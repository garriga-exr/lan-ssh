// License: see LICENSE file at root directory of `master` branch

/// # Wrapper for format!(), which wraps your message inside 'bold' tag
macro_rules! __b { ($($arg: tt)+) => {
    format!("\x1b[1m{}\x1b[m", format!($($arg)+))
};}

/// # Wrapper for format!(), which wraps your message inside a warning 'red color' tag
macro_rules! __w { ($($arg: tt)+) => {
    format!("\x1b[38;5;1m{}\x1b[39m", format!($($arg)+))
};}
