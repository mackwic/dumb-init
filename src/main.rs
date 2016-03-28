extern crate clap;
extern crate fern;
extern crate libc;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate time;

use clap::{App, Arg};

use std::env::var_os;

lazy_static! {
    // we test if it is set AND different to 0
    static ref IS_DEBUG : bool = Some("0".into()) != var_os("DUMB_INIT_DEBUG").or(Some("0".into()));
    // we test if it is not set OR equal to 0
    static ref USE_SETSID : bool = !(Some("0".into()) != var_os("DUMB_INIT_SETSID").or(Some("1".into())));
}

struct Forwarder {
    child_pid: Option<libc::c_int>
}

/*
 * dumb-init is a simple wrapper program designed to run as PID 1 and pass
 * signals to its children.
 *
 * Usage:
 *   ./dumb-init python -c 'while True: pass'
 *
 * To get debug output on stderr, run with '-v'.
 */

pub fn main() {
    let matches = App::new("dumb-init")
        .version("v1.0-alpha")
        .author("Thomas \"mackwic\" Wickham <mackwic@gmail.com>")
        .about("dumb-init is a simple processs supervisor that forwards signals to children. \n\
                It is designed to run as PID1 in minimal container environment.")
        .arg(Arg::with_name("single-child")
            .long("single-child")
            .short("c")
            .help("Run in single child mode. In this mode, signals are only proxified to the \
                   direct child and not any of its descendants"))
        .arg(Arg::with_name("verbose")
            .long("verbose")
            .short("v")
            .help("Print debugging information to stderr"))
        .arg(Arg::with_name("command")
            .required(true))
        .arg(Arg::with_name("args")
            .multiple(true))
        .get_matches();

    let log_level = if *IS_DEBUG {
        log::LogLevelFilter::Trace
    } else {
        log::LogLevelFilter::Info
    };

    let log_config = fern::DispatchConfig {
        format: Box::new(|msg: &str, level: &log::LogLevel, _location: &log::LogLocation| {
            format!("[{}][{}]\t{}", time::now().strftime("%Y-%m-%d][%H:%M:%S").unwrap(), level, msg)
        }),
        output: vec![fern::OutputConfig::stderr()],
        level: log_level
    };
    fern::init_global_logger(log_config, log_level).expect("unable to init logger");

    info!("Logger init success");
    debug!("Running in debug mode");

    if *USE_SETSID {
        debug!("Not running in setsid mode")
    }

    let forwarder = Forwarder { child_pid: None };

    for signum in 1..31 {
        if signum == libc::SIGKILL || signum == libc::SIGKILL || signum == libc::SIGCHLD {
            continue
        }

        unsafe {
            match libc::signal(signum, handle_signal as usize) {
                0 => (),
                _ => {
                    error!("Couldn't register signal handler for signal {}. Exiting.", signum);
                    std::process::exit(1)
                },
            }
        }
    }

    println!("{:?}", matches)
}

impl Forwarder {
    fn set_pid(&mut self, pid: libc::c_int) {
        self.child_pid = Some(pid);
    }

    fn forward_signal(&self, signum: libc::c_int) {
        if let Some(pid) = self.child_pid {
            let pid = if *USE_SETSID { -pid } else { pid };
            unsafe { libc::kill(pid, signum); }
            debug!("Forwarded signal {} to children (pid={})", signum, pid)
        } else {
            debug!("Didn't forward signal {}, no children exist yet.", signum)
        }
    }

    /*
     * The dumb-init signal handler.
     *
     * The main job of this signal handler is to forward signals along to our child
     * process(es). In setsid mode, this means signaling the entire process group
     * rooted at our child. In non-setsid mode, this is just signaling the primary
     * child.
     *
     * In most cases, simply proxying the received signal is sufficient. If we
     * receive a job control signal, however, we should not only forward it, but
     * also sleep dumb-init itself.
     *
     * This allows users to run foreground processes using dumb-init and to
     * control them using normal shell job control features (e.g. Ctrl-Z to
     * generate a SIGTSTP and suspend the process).
     *
     * The libc manual is useful:
     * https://www.gnu.org/software/libc/manual/html_node/Job-Control-Signals.html
     *
     * When running in setsid mode, however, it is not sufficient to forward
     * SIGTSTP/SIGTTIN/SIGTTOU in most cases. If the process has not added a custom
     * signal handler for these signals, then the kernel will not apply default
     * signal handling behavior (which would be suspending the process) since it is
     * a member of an orphaned process group.
     *
     * Sadly this doesn't appear to be well documented except in the kernel itself:
     * https://github.com/torvalds/linux/blob/v4.2/kernel/signal.c#L2296-L2299
     *
     * Forwarding SIGSTOP instead is effective, though not ideal; unlike SIGTSTP,
     * SIGSTOP cannot be caught, and so it doesn't allow processes a change to
     * clean up before suspending. In non-setsid mode, we proxy the original signal
     * instead of SIGSTOP for this reason.
    */
    fn handle_signal(&self, signum: libc::c_int) {
        debug!("Received signal {}", signum);
        use libc::*;

        match signum {
            SIGTSTP | // tty: background yourself
            SIGTTIN | // tty: stop reading
            SIGTTOU   // tty: stop writing
                => {
                    if *USE_SETSID {
                        debug!("Running in setsid mode, so forwarding SIGSTOP instead.");
                        self.forward_signal(SIGSTOP)
                    } else {
                        debug!("Not running in setsid mode, so forwarding the original signal ({})", signum);
                        self.forward_signal(signum)
                    }

                    debug!("Suspending self due to TTY signal");
                    unsafe { kill(getpid(), SIGSTOP); }
                },
            _ => self.forward_signal(signum)
        }
    }


}
