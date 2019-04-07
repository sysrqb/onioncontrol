use std::env;
use std::fmt::{Error as FmtError, Write as FmtWrite};
use std::fs::File;
use std::io::{Error as IoError, Read, Write as IoWrite};
use std::os::unix::net::UnixStream;
use std::str;
use std::str::Utf8Error;
use std::{thread, time};

const DEFAULT_CONTROL_SOCKET_PATH: &str = "/run/tor/control";
const DEFAULT_AUTHCOOKIE_PATH:     &str = "/run/tor/control.authcookie";

struct ControlConnection {
    control_socket_path: String,
    control_auth_cookie_path: String,
    control_socket: UnixStream,
}

impl ControlConnection {
    fn establish_connection() -> Result<ControlConnection, IoError> {
        // TODO: Parameterize and parse cookie file path from PROTOCOLINFO
        let control_socket_path = String::from(DEFAULT_CONTROL_SOCKET_PATH).clone();

        println!("Connecting to control socket");
        let conn_sockaddr = match UnixStream::connect(&control_socket_path) {
            Ok(s) => s,
            Err(r) => {
                println!("Failure while opening Unix domain socket '{}': {:?}",
                         control_socket_path, r);
                return Err(r);
            },
        };

        conn_sockaddr.set_nonblocking(true).unwrap();

        Ok(ControlConnection {
              control_socket_path: control_socket_path,
              control_auth_cookie_path: String::from(DEFAULT_AUTHCOOKIE_PATH).clone(),
              control_socket: conn_sockaddr
        })
    }

    fn read_from_file(&self, file: &mut File, output: &mut [u8]) -> Result<usize, IoError> {
        file.read(output)
    }

    fn is_eagain(&self, err: &IoError) -> bool {
        if let Some(raw_os_err) = err.raw_os_error() {
            if raw_os_err == 11 {
                // EAGAIN, Poll every 50 ms
                let fifty_millis = time::Duration::from_millis(50);
                thread::sleep(fifty_millis);
                return true;
            }
        }
        false
    }

    fn read_from_control_socket(&mut self, output: &mut [u8]) -> Result<usize, IoError> {
        loop {
            let res = self.control_socket.read(output);
            match res {
                Err(r) => {
                    if self.is_eagain(&r) {
                        continue;
                    }
                    return Err(r);
                },
                Ok(s) => return Ok(s),
            }
        }
    }

    fn read_all_from_control_socket(&mut self, output: &mut String) -> Result<usize, IoError> {
        loop {
            let res = self.control_socket.read_to_string(output);
            match res {
                Err(r) => {
                    if self.is_eagain(&r) {
                        continue;
                    }
                    return Err(r);
                },
                Ok(s) => return Ok(s),
            }
        }
    }

    fn write_to_control_socket(&mut self, input: &[u8]) -> Result<(), IoError> {
        self.control_socket.write_all(input)?;

        let line_end = "\r\n".as_bytes();
        self.control_socket.write_all(line_end)?;

        self.control_socket.flush()
    }

    fn open_cookie_file(&self) -> Result<File, IoError> {
        File::open(self.control_auth_cookie_path.clone())
    }

    // Note: hard-coding array of 32 u8 (COOKIE_SIZE)
    fn read_cookie_from_file(&self) -> Result<[u8; 32], String> {
        const COOKIE_SIZE: usize = 32;

        let mut cookie_file = match self.open_cookie_file() {
            Err(r) => {
                let err = format!("Failure while opening cookie file ({}): {:?}",
                              self.control_auth_cookie_path, r);
                return Err(err);
            },
            Ok(c) => c,
        };

        let mut cookie: [u8; COOKIE_SIZE] = [0; COOKIE_SIZE];
        let cookie_size = match self.read_from_file(&mut cookie_file, &mut cookie) {
            Err(r) => {
                let err = format!("Failure while reading cookie from cookie file: {:?}", r);
                return Err(err);
            },
            Ok(s) => s,
        };

        if cookie_size != COOKIE_SIZE {
            return Err("Cookie is the wrong size!".to_string());
        }

        Ok(cookie)
    }

    fn format_cookie(&self, raw_cookie: &[u8; 32]) -> Result<String, FmtError> {
        let mut buf = String::new();
        // Split across multiple lines with braces for readability
        let vec_result =
            raw_cookie.iter().map(|&c| {
                                  write!(&mut buf, "{:02X}", c)
            }).collect::<Vec<Result<(), FmtError>>>();
        for res in vec_result {
            if let Err(r) = res {
                return Err(r);
            }
        }
        Ok(buf)
    }

    fn join_string(&self, string: &Vec<String>) -> String {
        string.as_slice().join(" ")
    }

    fn get_str_from_bytes<'a>(&self, bytes: &'a [u8]) -> Result<&'a str, Utf8Error>  {
        str::from_utf8(bytes)
    }

    fn send_command(&mut self, command: &Vec<String>) -> Result<(), IoError> {
        let entire_command = self.join_string(command);
        println!("Sending '{}'", entire_command);
        self.write_to_control_socket(entire_command.as_bytes())
    }

    fn command_successful(&mut self) -> Result<(), ()> {
        let mut response_code: [u8; 3] = [0; 3];
        let response_code_len = match self.read_from_control_socket(&mut response_code) {
            Err(r) => {
                println!("Failure while reading authenticate response: {:?}", r);
                return Err(());
            },
            Ok(s) => s,
        };

        if response_code_len != 3 {
            println!("Response code is too short({}): {:?}", response_code_len, response_code);
            return Err(());
        }

        let resp_code = match self.get_str_from_bytes(&response_code) {
            Err(r) => {
                println!("Decoding response code failed: {:?}", r);
                return Err(());
            },
            Ok(r) => r,
        };

        if resp_code != "250" {
            println!("Response code is not 250: {:?}", resp_code);
            let mut message = String::new();
            if self.read_all_from_control_socket(&mut message).is_ok() {
                // Trim the trailing \r\n
                if message[message.len()-2..message.len()] == *"\r\n" {
                    message = message[..message.len()-2].to_string();
                }
                println!("Reason: '{}'", message);
            }
            return Err(());
        }
        println!("Found 250");

        Ok(())
    }

    fn get_ok(&mut self) -> Result<(), ()> {
        // " OK\r\n"
        let mut response_code: [u8; 5] = [0; 5];
        let response_code_len = match self.read_from_control_socket(&mut response_code) {
            Err(r) => {
                println!("Failure while reading ok string: {:?}", r);
                return Err(());
            },
            Ok(s) => s,
        };

        if response_code_len != 5 {
            println!("Response code is too short({}): {:?}", response_code_len, response_code);
            return Err(());
        }

        if self.get_str_from_bytes(&response_code).unwrap() != " OK\r\n" {
            println!("Response code is not ' OK\r\n': {:?}", response_code);
            return Err(());
        }

        Ok(())
    }

    fn authenticate(&mut self) -> Result<(), String> {
        let command: String = String::from("AUTHENTICATE");

        let raw_cookie = match self.read_cookie_from_file() {
            Err(r) => {
                let err = format!("Parsing cookie file failed: {:?}", r);
                return Err(err);
            },
            Ok(c) => c,
        };
        println!("Read cookie from file: {}", self.control_auth_cookie_path);

        let hex_cookie = match self.format_cookie(&raw_cookie) {
            Err(r) => {
                //println!("Formatting cookie failed: {:?}", r);
                let err = format!("Formatting cookie failed: {:?}", r);
                return Err(err);
            },
            Ok(c) => c,
        };

        let command = vec![command, hex_cookie];

        println!("Sending AUTHENTICATE command");
        match self.send_command(&command) {
            Err(r) => {
                println!("Writing to control socket failed: {:?}", r);
                return Err("Sending AUTHENTICATE failed".to_string());
            },
            Ok(_) => {}
        };

        println!("Checking success...");
        if self.command_successful().is_err() {
            return Err("AUTHENTICATE failed".to_string());
        }

        println!("Got 250...");
        if self.get_ok().is_err() {
            return Err("AUTHENTICATE failed, not Ok".to_string());
        }
        println!("And we have authentication!");

        Ok(())
    }

    fn get_info(&mut self, info: String) -> Result<(), ()> {
        let command = vec!["GETINFO".to_string(), info];
        match self.send_command(&command) {
            Err(r) => {
                println!("Writing to control socket failed: {:?}", r);
                return Err(());
            },
            Ok(_) => {},
        };

        if self.command_successful().is_err() {
            println!("Response code indicates a failure");
            return Err(());
        }

        Ok(())
    }

    fn set_events(&mut self, user_events: String) -> Result<(), ()> {
        let default_events = "CIRC CIRC_MINOR GUARD HS_DESC NETWORK_LIVENESS ORCONN STATUS_GENERAL STREAM STATUS_CLIENT".to_string();

        let events;
        if user_events.is_empty() {
            println!("Using default events");
            events = default_events;
        } else {
            events = user_events;
        }

        let command = vec!["SETEVENTS".to_string(), events];
        match self.send_command(&command) {
            Err(r) => {
                println!("Writing to control socket failed: {:?}", r);
                return Err(());
            },
            Ok(_) => {},
        };

        if self.command_successful().is_err() {
            println!("Response code indicates a failure");
            let mut message = String::new();
            match self.read_all_from_control_socket(&mut message) {
                Ok(_) => println!("Message: '{}'", message),
                Err(r) => println!("Error while reading remainder on socket: {:?}, {}", r, message),
            };
            return Err(());
        }

        Ok(())
    }

    fn send_signal(&mut self, signal: String) -> Result<(), ()> {
        let command = vec!["SIGNAL".to_string(), signal];
        match self.send_command(&command) {
            Err(r) => {
                println!("Writing to control socket failed: {:?}", r);
                return Err(());
            },
            Ok(_) => {},
        };

        if self.command_successful().is_err() {
            println!("Response code indicates a failure");
            return Err(());
        }

        Ok(())
    }

    // TODO Vendor chrono and use it directly for proper formating
    fn format_time(&self, now: time::SystemTime) -> String {
        // Copied from crono/datetime.rs
        let (sec, nsec) = match now.duration_since(time::SystemTime::UNIX_EPOCH) {
            Ok(dur) => (dur.as_secs() as i64, dur.subsec_nanos()),
            Err(e) => { // unlikely but should be handled
                let dur = e.duration();
                let (sec, nsec) = (dur.as_secs() as i64, dur.subsec_nanos());
                if nsec == 0 {
                    (-sec, 0)
                } else {
                    (-sec - 1, 1_000_000_000 - nsec)
                }
            },
        };

        let secs = format!("{}.{}", sec, nsec);
        return secs;
    }

    fn print_result(&mut self) {
        // buf is a circular buffer, we're done when it contains b'250 OK\r\n'
        let mut buf: [u8; 8] = [0; 8];

        let mut c: [u8; 1] = [0; 1];
        let now = time::SystemTime::now();

        // TODO: This isn't human-readable or meaningful
        print!("{}: ", self.format_time(now));

        loop {
            let count = match self.read_from_control_socket(&mut c) {
                Err(r) => {
                    println!("Failed while reading from socket: {:?}", r);
                    return;
                },
                Ok(count) => count,
            };
            
            if count == 0 {
                print!("\n");
                return;
            }

            // Set at the last byte of the slice
            buf[buf.len()-1] = c[0];

            let next = self.get_str_from_bytes(&c).unwrap();
            print!("{}", next);

            if next == "\n" {
                //print!("{} - ", self.format_time(time::SystemTime::now()));
                let now = time::SystemTime::now();
                print!("{} - ", self.format_time(now));
            }

            // "250 OK" may be sent on its own line, but we may only get " OK"
            // because the "250"-prefix was eaten by command_succesful().
            if buf.ends_with(b"\0\0\0 OK\r\n") || buf.ends_with(b"250 OK\r\n") {
                print!("\n");
                return;
            }

            // Requires stable, 1.26.0
            buf.rotate_left(1);
        }
    }

    fn print_events(&mut self) {
        let mut c: [u8; 1] = [0; 1];
        let now = time::SystemTime::now();
        // TODO: This isn't human-readable or meaningful
        print!("{}: ", self.format_time(now));

        loop {
            let count = match self.read_from_control_socket(&mut c) {
                Err(r) => {
                    println!("Failed while reading from socket: {:?}", r);
                    return;
                },
                Ok(count) => count,
            };
            
            if count == 0 {
                print!("\n");
                return;
            }

            let next = self.get_str_from_bytes(&c).unwrap();
            print!("{}", next);

            if next == "\n" {
                let now = time::SystemTime::now();
                print!("{} - ", self.format_time(now));
            }
        }
    }
}

enum RuntimeMode {
    GETINFO,
    SETEVENTS,
    SIGNAL,
}

fn print_help() {
    println!("Syntax: blah [-es] <args>");
    println!("  -e    enables SETEVENTS mode");
    println!("  -s    enables SIGNAL mode");
    println!("  GETINFO by default");
}

// Very hacky and minimal arg parsing
fn get_args() -> Option<(RuntimeMode, String)> {
    let mut mode = RuntimeMode::GETINFO;
    let args = env::args();

    // Skip the binary's name
    let mut args_iter = args.skip(1);

    let arg = match args_iter.next() {
        Some(a) => a,
        None => {
            println!("Missing arguments!");
            print_help();
            return None;
        },
    };

    let mut remaining_args = String::new();

    if arg == "-e" {
        mode = RuntimeMode::SETEVENTS;
    } else if arg == "-s" {
        mode = RuntimeMode::SIGNAL;
    } else {
        write!(remaining_args, "{} ", arg).unwrap();
    }

    // TODO use join instead
    for arg in args_iter {
        write!(remaining_args, "{} ", arg).unwrap();
    }

    if remaining_args.is_empty() {
        // Add the trailing space expected below
        write!(remaining_args, " ").unwrap();
    }

    // Drop the trailing space in line
    Some((mode, remaining_args[..(remaining_args.len()-1)].to_string()))
}

fn main() {
    println!("Hello, world!");
    let mut conn = match ControlConnection::establish_connection() {
        Ok(c) => c,
        Err(_) => return,
    };

    println!("Control socket connection established: {}", conn.control_socket_path);
    match conn.authenticate() {
      Err(r) => {
          println!("{}", r);
          return;
      },
      Ok(_) => {
          println!("Successfully authenticated");
      }
    };

    match get_args() {
        Some((mode, args)) => {
            if let RuntimeMode::GETINFO = mode {
                conn.get_info(args).expect("GETINFO failed");
                conn.print_result();
            } else if let RuntimeMode::SETEVENTS = mode {
                conn.set_events(args).expect("SETEVENTS failed");
                conn.print_events();
            } else if let RuntimeMode::SIGNAL = mode {
                conn.send_signal(args).expect("SETEVENTS failed");
                conn.print_result();
            }
        },
        None => (),
    };
}
