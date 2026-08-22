//! Subprocess supervision: run a command, feed stdin, drain both pipes
//! concurrently (required on Windows — a full pipe buffer deadlocks a child
//! that is still writing), and enforce a wall-clock timeout. The synchronous
//! runner remains until the Tokio scheduler arrives in v0.2.
//!
//! Windows subtleties this module owns: `.cmd` shims (npm installs) mean the
//! direct child is `cmd.exe`, so every invocation is placed in a private Job
//! Object before its suspended primary thread is allowed to execute. Closing
//! that handle kills ordinary descendants even when the direct child exits
//! successfully or Tactus is terminated. Explicit cleanup uses the same job
//! and a bounded wait; it never shells out to a PID-based tree walker. Any
//! process that inherited a pipe handle must not be able to stall the drain —
//! readers accumulate into shared buffers that are snapshotted after a bounded
//! grace instead of joined unconditionally.
//!
//! Unix subtleties are the mirror image: each invocation gets an isolated
//! process group so a timeout can kill every member, but that isolation
//! also stops terminal interrupts reaching the child automatically. A tiny
//! process-wide signal monitor below preserves inherited ignored and custom
//! handlers,
//! coordinates SIGINT/SIGTERM/SIGHUP/SIGQUIT termination, and proxies terminal
//! suspension/continuation. It waits out any spawn-registration race, blocks
//! launches across a suspension transition, and uses a descriptor-scrubbed
//! guard process to close the last signal-to-stop race. A separate cleanup
//! reaper survives even an uncatchable Tactus SIGKILL. Together the monitor and
//! reaper stop and clean every active process group before ownership is
//! released. A host runner does not claim to contain code that deliberately
//! leaves that group with `setsid`/`setpgid`; the external/container runner
//! described in DESIGN.md is the boundary for hostile or daemonising repository
//! code. Pretending otherwise would require racy process-table inference on
//! macOS, where there is no unprivileged descendant-containment primitive.
//! Within the host-runner contract, run ownership cannot be handed to a resume
//! -- or appear suspended -- while an isolated agent group is running.
// LEGACY-EFFECT: this module is in the **frozen legacy section** of
// `effects/allowlist.toml`, which carries its justification and the condition
// under which the section shrinks. `decisions.effect_site_inventory.mechanism` (2).
#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]

use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::TactusError;
use crate::topology::effects::{Injection, InjectionMode, SubEffectPoint};

/// The parent-side containment steps of one spawn, told to whoever is watching.
///
/// `decisions.effect_site_inventory.containment_sub_effects`: "the process
/// funnel exposes hook points for platform containment steps, each a
/// Topology/Shared site with documented residue and recovery". PR3 declared the
/// eight points ([`SubEffectPoint`]); PR4 makes them execute, and this is the
/// interface through which they do.
///
/// Production passes [`NoHooks`], which answers [`Injection::Proceed`] to
/// everything and costs a virtual call per containment step. The ST-07 subset
/// passes [`crate::runner::HarnessHooks`], which records into PR3's
/// `HookHarness` and returns whatever the suite armed.
pub trait SpawnHooks {
    /// The funnel reached `point`. The answer says what it must do there.
    fn point(&mut self, point: SubEffectPoint) -> Injection;

    /// The funnel reached `point`, at the coordinate that mode's fault belongs
    /// at.
    ///
    /// A point whose two modes fire at two coordinates cannot be consulted
    /// once. `Spawn.AmbientJobJoined` is the one:
    /// `containment_sub_effects` gives it an error contract — "failure refuses
    /// the write command" — which stands *in place of* establishing the job, so
    /// it is consulted **before** the join; and it gives it the kill claim "a
    /// coordinator kill after any of these leaves no host process (the ambient
    /// handle closes …)", which is only true **after** the join, because before
    /// it there is no handle to close.
    ///
    /// The default answers with [`Self::point`], so an observer that does not
    /// distinguish modes behaves exactly as it did.
    fn point_mode(&mut self, point: SubEffectPoint, mode: InjectionMode) -> Injection {
        let _ = mode;
        self.point(point)
    }

    /// The funnel created a child and has not yet contained it.
    ///
    /// Called between `CreateProcess`/`fork` and the next containment step, so
    /// an observer that is about to inject a kill can record the identity that
    /// must not survive the coordinator. The Windows stub test needs the pid
    /// *and* the creation time, because Windows reuses pids, and only the
    /// funnel knows the pid before it dies.
    fn child_created(&mut self, _pid: u32) {}
}

/// What production passes: nothing is armed and nothing is recorded.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoHooks;

impl SpawnHooks for NoHooks {
    fn point(&mut self, _point: SubEffectPoint) -> Injection {
        Injection::Proceed
    }
}

/// Do what a hook answered.
///
/// [`Injection::Kill`] aborts. Not `panic!` and not `std::process::exit`:
/// the whole claim under test is that a coordinator which dies **without
/// running any cleanup** still leaves no host process, and both of those run
/// destructors — including the one that closes the very job handle whose
/// close-on-death is the mechanism.
fn apply(injection: Injection, point: SubEffectPoint) -> Result<(), TactusError> {
    match injection {
        Injection::Proceed => Ok(()),
        Injection::Kill => std::process::abort(),
        Injection::Error => Err(TactusError::Refused {
            message: format!(
                "the process funnel was made to fail at its `{point}` containment step"
            ),
        }),
    }
}

/// What a **memoised** one-shot establishment reports to a caller.
///
/// A `OnceLock` holding a `Result` has exactly two arms and one of them is not
/// otherwise reachable in a test: the coordinator joins one ambient job for its
/// whole life, so a process that memoised a success can never observe a failure
/// and a process that memoised a failure never got a coordinator. Every ambient
/// failure this suite can build is the *injected* one, which fires strictly
/// before the memo is consulted — so `Err(_) => Ok(())` here left the whole
/// suite green while a Windows coordinator whose `CreateJobObjectW` failed
/// carried on into `run`/`resume` with no ambient kill-on-close job at all: the
/// degraded mode `crash_reconstruction` forbids ("no degraded mode; deferred")
/// and `expected_failures_refusals[1]` requires a startup refusal for
/// (`PR5-CORRECTNESS-010`).
///
/// Generic and platform-independent **so that arm can be executed on any
/// machine**. The value it decides about is Windows-only; the decision is not,
/// and a decision only one platform can test is a decision one platform never
/// tests.
///
/// # Errors
///
/// The memoised diagnostic, verbatim — the caller renders it into the refusal,
/// so a *fresh* message here would name something that did not happen.
// Unix has no ambient job and therefore no production caller; the test below is
// the only one there, and running it there is the point. `dead_code` is not a
// governed lint (`effects::GOVERNED_LINTS`), so this is outside the
// allow-placement scan rather than an exception to it.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn memoised_outcome<T>(memo: &Result<T, String>) -> Result<(), String> {
    match memo {
        Ok(_) => Ok(()),
        Err(message) => Err(message.clone()),
    }
}

/// [`apply`] for the funnel steps whose only declared mode is `Kill`.
///
/// `SubEffectPoint::modes` gives every containment point except
/// `AmbientJobJoined` kill mode alone, because the packet gives only the
/// ambient join an error contract to return through ("failure refuses the
/// write command"). An `Error` here can therefore only come from a hand-written
/// observer, and it is surfaced as a spawn failure rather than silently
/// ignored.
#[cfg(windows)]
fn apply_io(injection: Injection, point: SubEffectPoint) -> std::io::Result<()> {
    match injection {
        Injection::Proceed => Ok(()),
        Injection::Kill => std::process::abort(),
        Injection::Error => Err(std::io::Error::other(format!(
            "the process funnel was made to fail at its `{point}` containment step"
        ))),
    }
}

#[derive(Debug, Clone)]
pub struct ProcessOutput {
    /// Exit code if the process exited normally; `None` when killed for a
    /// timeout/output limit or terminated by a signal.
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    /// Wall clock from spawn to process exit (not including pipe drain).
    pub duration: Duration,
    pub timed_out: bool,
    /// The child exceeded the bounded stdout or stderr capture allowance and
    /// its owned process tree was terminated.
    pub output_limited: bool,
}

/// How long to keep draining pipes after the process is gone. Normally EOF is
/// immediate; the grace only caps the pathological case of an orphaned
/// grandchild still holding a write handle.
const DRAIN_GRACE_EXIT: Duration = Duration::from_secs(2);
const DRAIN_GRACE_KILL: Duration = Duration::from_millis(500);
/// Per stream. Readers continue draining after this point so the child cannot
/// block on a full pipe while the supervisor notices and terminates its tree.
const OUTPUT_LIMIT_BYTES: usize = 16 * 1024 * 1024;

/// A direct child plus the platform primitive that owns its ordinary
/// descendants. Keeping ownership beside `Child` prevents a successful wait
/// from accidentally bypassing tree settlement.
struct ProcessTree {
    child: Child,
    #[cfg(windows)]
    job: windows_job::Job,
}

impl ProcessTree {
    fn spawn(command: &mut Command, hooks: &mut dyn SpawnHooks) -> std::io::Result<Self> {
        #[cfg(windows)]
        {
            let (child, job) = windows_job::spawn_suspended_in_job(command, hooks)?;
            Ok(Self { child, job })
        }
        #[cfg(not(windows))]
        {
            let child = command.spawn()?;
            hooks.child_created(child.id());
            Ok(Self { child })
        }
    }

    /// The direct child has already exited. Windows descendants remain job
    /// members, so terminate and observe the job empty before returning its
    /// status. Unix process-group settlement is owned by `termination`.
    #[cfg(windows)]
    fn finish_direct_exit(&mut self) -> Result<(), TactusError> {
        self.job
            .terminate_and_wait()
            .map_err(|error| TactusError::Agent {
                message: format!("settling the Windows agent job after direct-child exit: {error}"),
            })?;
        Ok(())
    }
}

impl Deref for ProcessTree {
    type Target = Child;

    fn deref(&self) -> &Self::Target {
        &self.child
    }
}

impl DerefMut for ProcessTree {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.child
    }
}

/// Run `command`, writing `stdin_data` to the child's stdin, with a hard
/// wall-clock timeout. On timeout the child's owned process group is killed and
/// the partial output captured so far is returned with `timed_out = true`
/// (§14: timeout is an attempt failure with the partial transcript as feedback).
/// Delegates to [`run_with_timeout_hooked`] with no observer rather than
/// calling the private entry point beside it: `invariants_preserved[0]` is
/// "process supervision, timeout, output capture and adapter parsing
/// unchanged", and two call sites each passing [`OUTPUT_LIMIT_BYTES`] are two
/// values that can drift. There is one, and it is this one.
pub fn run_with_timeout(
    command: Command,
    stdin_data: &str,
    timeout: Duration,
) -> Result<ProcessOutput, TactusError> {
    run_with_timeout_hooked(command, stdin_data.as_bytes(), timeout, &mut NoHooks)
}

/// The process funnel with its containment sub-effect points observable.
///
/// The same supervision, timeout and capture as [`run_with_timeout`] — this is
/// the one function both go through, which is what makes "every CLI and gate
/// process executes through Runner" a structural claim rather than a
/// convention. `stdin_data` is bytes here because a [`crate::runner::CommandSpec`]
/// carries bytes.
///
/// # Errors
///
/// Spawn failure, supervision failure, or a fault the observer injected.
pub fn run_with_timeout_hooked(
    command: Command,
    stdin_data: &[u8],
    timeout: Duration,
    hooks: &mut dyn SpawnHooks,
) -> Result<ProcessOutput, TactusError> {
    run_with_timeout_and_limit(command, stdin_data, timeout, OUTPUT_LIMIT_BYTES, hooks)
}

fn run_with_timeout_and_limit(
    mut command: Command,
    stdin_data: &[u8],
    timeout: Duration,
    output_limit: usize,
    hooks: &mut dyn SpawnHooks,
) -> Result<ProcessOutput, TactusError> {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Enter before `spawn`: if an interrupt arrives in the narrow interval
    // between creating the child and learning its pid, the signal monitor
    // waits for this registration rather than terminating Tactus first and
    // orphaning the new process group.
    #[cfg(unix)]
    let mut termination = termination::Supervisor::begin()?;
    // `Spawn.ReaperStarted`: "fork of the per-invocation reaper, which takes
    // its shared cleanup hold R28". `begin` returning Ok is exactly that
    // having happened, and nothing else in this function can have happened
    // yet.
    #[cfg(unix)]
    apply(
        hooks.point(SubEffectPoint::ReaperStarted),
        SubEffectPoint::ReaperStarted,
    )?;
    #[cfg(unix)]
    termination.prepare(&mut command);

    let started = Instant::now();
    let mut child = ProcessTree::spawn(&mut command, hooks).map_err(|e| TactusError::Agent {
        message: format!(
            "failed to spawn `{}`: {e}",
            command.get_program().to_string_lossy()
        ),
    })?;
    // `Spawn.PreExecPgidAndRegister`. Two coordinates, and they are not the
    // same one:
    //
    // * The **operation** is in the forked child before `exec` — `setpgid(0,0)`
    //   and the reaper registration, in `termination::Supervisor::prepare`'s
    //   `pre_exec` closure. That is where the packet puts it ("in the child
    //   before exec") and where it is.
    // * The **injection** is here, parent-side, immediately after `spawn`
    //   returns `Ok`. This point's only declared mode is `Kill`
    //   (`SubEffectPoint::modes`), a kill is a *coordinator* death, and the
    //   packet's claim for it — "a coordinator kill after any of these leaves a
    //   group the reaper settles while holding R28" — is true only once the
    //   child exists and its group does. A kill delivered inside the forked
    //   child would end the fork, not the coordinator, and would leave no group
    //   at all. An observer hook cannot run there in any case: after `fork` in a
    //   multithreaded process only async-signal-safe calls are permitted, and
    //   every real observer locks and allocates. The packet contemplates
    //   exactly this: "these are parent-side **or** pre-exec points the harness
    //   controls".
    //
    // Fired unconditionally, because `spawn` returning `Ok` *is* the evidence
    // the closure ran: `std` reports a `pre_exec` error through the child's
    // CLOEXEC status pipe and returns `Err`. The kernel oracle
    // (`child_leads_its_own_group`) is a second, independent witness and lives
    // in the tests — as a guard here it could only ever produce a false
    // negative, silently dropping the point for a child that left its own group
    // after `exec` (DESIGN.md:398-402 puts such a process outside host
    // guarantees; it does not make it invisible).
    #[cfg(unix)]
    apply(
        hooks.point(SubEffectPoint::PreExecPgidAndRegister),
        SubEffectPoint::PreExecPgidAndRegister,
    )?;
    // `Spawn.Exec`: `Command::spawn` reports a failed `execvp` through its own
    // CLOEXEC status pipe and returns `Err`, so reaching here is the exec
    // having succeeded.
    #[cfg(unix)]
    apply(hooks.point(SubEffectPoint::Exec), SubEffectPoint::Exec)?;
    #[cfg(unix)]
    if let Err(error) = termination.register(child.id()) {
        // Drop the pre-exec reaper first: it still has an anchor pinning this
        // child's group identity and will kill every member before returning.
        drop(termination);
        kill_tree(&mut child)?;
        return Err(error);
    }
    // `Spawn.Registered`: "parent-side registration".
    #[cfg(unix)]
    apply(
        hooks.point(SubEffectPoint::Registered),
        SubEffectPoint::Registered,
    )?;

    // Feed stdin from its own thread: the child may not read stdin until it
    // has written output, and this thread must not block the pipe drains.
    let stdin_bytes = stdin_data.to_vec();
    let stdin_handle = child.stdin.take();
    let stdin_thread = thread::spawn(move || {
        if let Some(mut pipe) = stdin_handle {
            // A child that exits without reading stdin breaks the pipe; that
            // is its prerogative, not an error.
            let _ = pipe.write_all(&stdin_bytes);
        }
    });

    let stdout_drain = child
        .stdout
        .take()
        .map(|pipe| Drain::start(pipe, output_limit));
    let stderr_drain = child
        .stderr
        .take()
        .map(|pipe| Drain::start(pipe, output_limit));

    let mut timed_out = false;
    let mut output_limited = false;
    #[cfg(unix)]
    let code = loop {
        match child_exited_unreaped(&child) {
            Ok(true) => {
                // Leave the exited leader as a zombie until cleanup completes:
                // its PID pins the PGID, so no unrelated group can reuse the
                // numeric id between observation and the final signal.
                if let Err(error) = termination.finish() {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(error);
                }
                let status = child.wait().map_err(|e| TactusError::Agent {
                    message: format!("reaping agent process: {e}"),
                })?;
                break status.code();
            }
            Ok(false) => {
                if drain_limit_exceeded(&stdout_drain, &stderr_drain) {
                    output_limited = true;
                    if let Err(error) = termination.finish() {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(error);
                    }
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                } else if started.elapsed() >= timeout {
                    timed_out = true;
                    if let Err(error) = termination.finish() {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(error);
                    }
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                let cleanup = termination.finish();
                let _ = child.kill();
                let _ = child.wait();
                cleanup?;
                return Err(TactusError::Agent {
                    message: format!("waiting on agent process: {e}"),
                });
            }
        }
    };
    #[cfg(not(unix))]
    let code = loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                child.finish_direct_exit()?;
                break status.code();
            }
            Ok(None) => {
                if drain_limit_exceeded(&stdout_drain, &stderr_drain) {
                    output_limited = true;
                    kill_tree(&mut child)?;
                    break None;
                } else if started.elapsed() >= timeout {
                    timed_out = true;
                    kill_tree(&mut child)?;
                    break None;
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                kill_tree(&mut child)?;
                return Err(TactusError::Agent {
                    message: format!("waiting on agent process: {e}"),
                });
            }
        }
    };
    let duration = started.elapsed();

    let grace = if timed_out || output_limited {
        DRAIN_GRACE_KILL
    } else {
        DRAIN_GRACE_EXIT
    };
    // Bounded like the read drains: a prompt larger than the pipe buffer plus
    // an orphan holding the read end would otherwise block write_all forever
    // and hang the supervisor past its own timeout. Abandoning the thread is
    // safe — it owns its handle and exits when the last reader closes.
    let stdin_deadline = Instant::now() + grace;
    while !stdin_thread.is_finished() && Instant::now() < stdin_deadline {
        thread::sleep(Duration::from_millis(20));
    }
    if stdin_thread.is_finished() {
        let _ = stdin_thread.join();
    }
    let (stdout, stdout_limited) = stdout_drain.map(|d| d.collect(grace)).unwrap_or_default();
    let (stderr, stderr_limited) = stderr_drain.map(|d| d.collect(grace)).unwrap_or_default();
    output_limited |= stdout_limited || stderr_limited;

    Ok(ProcessOutput {
        code,
        stdout,
        stderr,
        duration,
        timed_out,
        output_limited,
    })
}

fn drain_limit_exceeded(stdout: &Option<Drain>, stderr: &Option<Drain>) -> bool {
    stdout.as_ref().is_some_and(Drain::limit_exceeded)
        || stderr.as_ref().is_some_and(Drain::limit_exceeded)
}

/// Kill the whole process tree. Killing only the direct child is not enough
/// when it is a `cmd.exe` shim: the real agent process would survive, keep
/// running, and keep the pipes open.
fn kill_tree(child: &mut ProcessTree) -> Result<(), TactusError> {
    #[cfg(windows)]
    {
        let cleanup = child.job.terminate_and_wait();
        let _ = child.kill();
        let _ = child.wait();
        cleanup.map_err(|error| TactusError::Agent {
            message: format!("terminating the Windows agent job: {error}"),
        })
    }
    #[cfg(not(windows))]
    {
        #[cfg(unix)]
        if let Ok(pid) = i32::try_from(child.id()) {
            // SAFETY: `run_with_timeout` put this child in a new process group
            // whose id is the child's pid. A negative pid targets that group only.
            let _ = unsafe { libc::kill(-pid, libc::SIGKILL) };
        }
        let _ = child.kill();
        let _ = child.wait();
        Ok(())
    }
}

/// Whether `pid` leads its own Unix process group.
///
/// The independent witness that `Spawn.PreExecPgidAndRegister`'s operation ran
/// in the forked child. Asks the kernel, not this crate: `getpgid(pid) == pid`
/// is true exactly when the pre-exec closure's `setpgid(0, 0)` ran. A child
/// that has exited but not been reaped still answers, because its pid is
/// pinned by the zombie.
///
/// Test-only on purpose: as a production guard it could only ever *withhold*
/// the point, never add information (see the comment at the injection
/// coordinate).
#[cfg(all(unix, test))]
pub(crate) fn child_leads_its_own_group(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    // SAFETY: `getpgid` reads process-table state for a pid this process owns
    // as a child and has not reaped; it borrows nothing.
    let pgid = unsafe { libc::getpgid(pid) };
    pgid == pid
}

/// Join the coordinator's ambient kill-on-close Job Object (INV-18).
///
/// > on Windows every host child is a member of the coordinator's ambient
/// > kill-on-close Job Object from creation
///
/// enforced by "ambient job joined at write-command startup (refusal
/// otherwise)". Idempotent: the job is a process-wide singleton established
/// once and held for the life of the process, because a handle that is ever
/// closed deliberately would terminate every member — including, since the
/// coordinator joins it too, the coordinator.
///
/// This closes the window the private per-invocation job cannot: between
/// `CreateProcess` and `AssignProcessToJobObject` the child belongs to no
/// private job, so a coordinator killed in that window used to leave a
/// suspended stub with no owner. A child created by an ambient-job member is a
/// member at creation, so there is no such window.
///
/// On Unix this does nothing and says so: containment there is the isolated
/// process group and the per-invocation reaper, and the packet declares
/// `AmbientJobJoined` a Windows point
/// (`decisions.effect_site_inventory.containment_sub_effects`). The hook is not
/// consulted here either — recording a Windows containment point as executed
/// on a Unix host would let a Linux CI cell claim Windows coverage.
///
/// # Errors
///
/// [`TactusError::Refused`] with a diagnostic when the job cannot be created
/// or joined. The caller refuses the write command before any effect.
#[cfg(windows)]
pub fn join_ambient_job(hooks: &mut dyn SpawnHooks) -> Result<(), TactusError> {
    join_ambient_job_with(hooks, windows_job::join_ambient)
}

/// [`join_ambient_job`] over an explicit join step.
///
/// The parameter exists because the real one cannot fail twice: `join_ambient`
/// memoises its answer in a process-wide `OnceLock` — it must, since the
/// coordinator joins exactly one ambient job for its whole life — so a test
/// binary that has ever joined successfully can never again observe a failure,
/// and one that observes a failure can never join. The suite's only ambient
/// failure was therefore the *injected* one, which fires **before** this step
/// and so proves nothing about what this function does with a real error: the
/// call could be `let _ = windows_job::join_ambient();` and every test would
/// still pass while `run` and `resume` dispatched with no ambient job at all.
///
/// # Errors
///
/// [`TactusError::Refused`] carrying `join`'s own diagnostic.
#[cfg(windows)]
fn join_ambient_job_with(
    hooks: &mut dyn SpawnHooks,
    join: impl FnOnce() -> Result<(), String>,
) -> Result<(), TactusError> {
    // The error-return coordinate is *before* the join: the point's error
    // contract is "failure refuses the write command", so an injected failure
    // stands in place of establishing the job rather than following a job that
    // was in fact established. A refusal here leaves no ambient job, no child,
    // and nothing to reclaim.
    apply(
        hooks.point_mode(SubEffectPoint::AmbientJobJoined, InjectionMode::ErrorReturn),
        SubEffectPoint::AmbientJobJoined,
    )
    .map_err(|_| TactusError::Refused {
        message: AMBIENT_REFUSAL_PREFIX.to_owned() + AMBIENT_REFUSAL_SIMULATED,
    })?;
    join().map_err(|message| TactusError::Refused {
        message: format!("{AMBIENT_REFUSAL_PREFIX}{message}. No process was spawned"),
    })?;
    // The kill coordinate is *after* it, because that is where the point's own
    // claim is true: "a coordinator kill after any of these leaves no host
    // process (the ambient handle closes and the kernel terminates the stub or
    // tree)". Injected before the join there would be no handle to close, and
    // the observation would sit on the wrong side of the sub-effect it names.
    apply(
        hooks.point_mode(SubEffectPoint::AmbientJobJoined, InjectionMode::Kill),
        SubEffectPoint::AmbientJobJoined,
    )
}

/// See the Windows implementation. On Unix this is a no-op that returns `Ok`.
///
/// # Errors
///
/// Never on Unix.
#[cfg(not(windows))]
pub fn join_ambient_job(_hooks: &mut dyn SpawnHooks) -> Result<(), TactusError> {
    Ok(())
}

/// The opening words of every ambient-job refusal, so a caller and a test can
/// recognise one without matching on a whole sentence.
pub const AMBIENT_REFUSAL_PREFIX: &str = concat!(
    "cannot start a write command: on Windows every child must be a member of ",
    "the coordinator's ambient kill-on-close Job Object from creation ",
    "(INV-18), and "
);

/// The tail of the refusal an injected join failure produces.
pub const AMBIENT_REFUSAL_SIMULATED: &str = concat!(
    "the ambient Job Object could not be established (simulated failure). ",
    "No process was spawned"
);

/// Whether the process `pid` created at `creation_time` is still running.
///
/// The pid alone is not an identity — Windows reuses pids — so both halves are
/// checked, and "running" is `WaitForSingleObject` timing out rather than an
/// exit code, because a job-terminated process's exit code is not ours to
/// predict. A pid that cannot be opened, or that opens onto a process created
/// at another time, is not this process.
#[cfg(windows)]
#[must_use]
pub fn process_alive(pid: u32, creation_time: u64) -> bool {
    windows_job::process_alive(pid, creation_time)
}

/// When the process `pid` was created, as a raw FILETIME, or `None` if it
/// cannot be opened.
#[cfg(windows)]
#[must_use]
pub fn process_creation_time(pid: u32) -> Option<u64> {
    windows_job::process_creation_time(pid)
}

/// Whether this process has joined its ambient Job Object.
#[cfg(windows)]
#[must_use]
pub fn ambient_job_established() -> bool {
    windows_job::ambient_established()
}

/// Whether `pid` is a member of this process's ambient Job Object, or `None`
/// when there is no ambient job or the process cannot be opened.
///
/// INV-18's claim, asked of the kernel: "every host child is a member of the
/// coordinator's ambient kill-on-close Job Object from creation".
#[cfg(windows)]
#[must_use]
pub fn child_in_ambient_job(pid: u32) -> Option<bool> {
    windows_job::ambient_contains(pid)
}

/// Memoise an ambient establishment **failure**, before anything has joined.
///
/// Test-only, and it spends this process's one ambient cell — so it belongs
/// only in a subprocess helper. It exists because the failure it plants is the
/// one no machine can produce on demand: `CreateJobObjectW` and
/// `AssignProcessToJobObject` succeed on a working Windows host, and the memo
/// means a process only ever sees one answer. Returns whether the cell was
/// still free.
#[cfg(all(windows, test))]
pub(crate) fn poison_ambient_for_tests(message: &str) -> bool {
    windows_job::poison_ambient_for_tests(message)
}

/// Arm this process's cleanup reapers to kill the coordinator's labeled
/// containers when the coordinator dies, or disarm them with `None`.
///
/// `decisions.admission_and_leases.permits.os_matrix`, in full:
///
/// > Linux and macOS (`cfg(unix)`): the cleanup reaper survives coordinator
/// > death, settles the dead coordinator's process groups while holding R28,
/// > and **additionally kills the dead coordinator's labeled containers**,
/// > closing the orphan window; Windows: **no reaper**; … containers are
/// > reclaimed at the **next write-command start** (orphan window until then;
/// > documented; a portable watchdog is deferred).
///
/// So this is a **no-op on Windows**, and that is the documented half rather
/// than an omission: [`crate::runner::container::orphan_window`] is the value
/// that says so and `runner::container::tests::windows_orphan_window_documented`
/// is what asserts the platform and the code agree.
///
/// The scope is read **before** the fork, by every reaper started after this
/// call: a reaper already running keeps the scope it was started with, because
/// it is a `fork`-only child that cannot be handed anything afterwards.
///
/// # Errors
///
/// Whatever building the argument vectors returns — on Unix, a scope whose
/// rendered strings carry an interior NUL.
pub fn set_container_reclaim_scope(
    scope: Option<&crate::runner::container::census::ReaperContainerScope>,
) -> Result<(), TactusError> {
    #[cfg(unix)]
    {
        termination::set_container_reclaim_scope(scope)
    }
    #[cfg(not(unix))]
    {
        let _ = scope;
        Ok(())
    }
}

#[cfg(windows)]
mod windows_job {
    use std::io;
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    use std::process::{Child, Command};
    use std::ptr;
    use std::thread;
    use std::time::{Duration, Instant};

    use std::sync::OnceLock;

    use windows_sys::Win32::Foundation::{
        CloseHandle, FILETIME, HANDLE, INVALID_HANDLE_VALUE, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, IsProcessInJob, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
        QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_SUSPENDED, GetCurrentProcess, GetProcessTimes, OpenProcess, OpenThread,
        PROCESS_QUERY_LIMITED_INFORMATION, ResumeThread, THREAD_SUSPEND_RESUME,
        WaitForSingleObject,
    };

    use super::{SpawnHooks, SubEffectPoint, apply_io};

    const CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

    /// A non-inheritable Job Object configured before any supervised code can
    /// run. The OS closes this handle on abrupt conductor death, and
    /// KILL_ON_JOB_CLOSE then terminates every ordinary descendant.
    pub(super) struct Job {
        handle: HANDLE,
    }

    /// The real `CreateJobObjectW`, as [`Job::create`] passes it.
    fn real_create_job() -> HANDLE {
        // SAFETY: null security attributes and name request an unnamed,
        // non-inheritable job owned solely by this process.
        unsafe {
            windows_sys::Win32::System::JobObjects::CreateJobObjectW(ptr::null(), ptr::null())
        }
    }

    /// The real `SetInformationJobObject`, as [`Job::create`] passes it.
    fn real_configure_job(
        handle: HANDLE,
        limits: &JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        size: u32,
    ) -> i32 {
        // SAFETY: `limits` has exactly the layout and lifetime required by
        // JobObjectExtendedLimitInformation; `handle` is live.
        unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                ptr::from_ref(limits).cast(),
                size,
            )
        }
    }

    /// The real `TerminateJobObject`, as [`Job::terminate_and_wait`] passes it.
    fn real_terminate_job(handle: HANDLE) -> i32 {
        // SAFETY: the handle remains live for this call and the requested exit
        // code has no semantic meaning outside this private job.
        unsafe { TerminateJobObject(handle, 1) }
    }

    /// The real `QueryInformationJobObject`, as the accounting callers pass it.
    fn real_query_accounting(
        handle: HANDLE,
        accounting: &mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    ) -> i32 {
        // SAFETY: the output buffer is correctly typed and sized and the
        // optional returned-length pointer is not needed.
        unsafe {
            QueryInformationJobObject(
                handle,
                JobObjectBasicAccountingInformation,
                ptr::from_mut(accounting).cast(),
                u32::try_from(size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>())
                    .expect("job accounting structure fits in u32"),
                ptr::null_mut(),
            )
        }
    }

    impl Job {
        fn create() -> io::Result<Self> {
            Self::create_with(real_create_job, real_configure_job)
        }

        /// [`Job::create`] over the two Win32 calls it makes.
        ///
        /// The same reason `create_ambient` takes its assignment call: on a
        /// working machine `CreateJobObjectW` and `SetInformationJobObject`
        /// always succeed, so both failure branches are unreachable in every
        /// real test and either could be inverted with the whole suite green —
        /// while `crash_reconstruction`'s "if the ambient job cannot be
        /// **created** or joined the write command refuses at startup" and
        /// INV-18's "refusal before any effect if the ambient job cannot be
        /// established" silently stopped holding. The join had a seam; these
        /// two did not, which made the guarantee asserted for one third of the
        /// sentence that states it.
        ///
        /// `configure` is handed the limit structure rather than a raw
        /// pointer, so a test can also read what is being asked for:
        /// `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` is the whole fail-safe, and a
        /// job configured with any other flag would still return success here.
        fn create_with(
            create: impl FnOnce() -> HANDLE,
            configure: impl FnOnce(HANDLE, &JOBOBJECT_EXTENDED_LIMIT_INFORMATION, u32) -> i32,
        ) -> io::Result<Self> {
            let handle = create();
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            let job = Self { handle };
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let size = u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                .expect("job information structure fits in u32");
            if configure(job.handle, &limits, size) == 0 {
                // `job` drops here, closing the handle: an unconfigured job is
                // not a job this process may keep.
                return Err(io::Error::last_os_error());
            }
            Ok(job)
        }

        pub(super) fn terminate_and_wait(&self) -> io::Result<()> {
            self.terminate_and_wait_with(real_terminate_job, real_query_accounting)
        }

        /// [`Job::terminate_and_wait`] over the Win32 calls it makes.
        ///
        /// DESIGN.md:402 — "Direct-child success and timeout both terminate
        /// and **boundedly observe that job empty**". Both halves of that
        /// sentence are unobservable from outside on a working machine: a real
        /// job empties immediately, so an implementation that skipped the
        /// observation entirely, and one that observed without a bound, both
        /// return promptly and leave nothing behind for a test to see. The
        /// accounting seam is what makes "observe" and "bounded" separate
        /// facts.
        pub(super) fn terminate_and_wait_with(
            &self,
            terminate: impl FnOnce(HANDLE) -> i32,
            query: impl Fn(HANDLE, &mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION) -> i32,
        ) -> io::Result<()> {
            if terminate(self.handle) == 0 {
                return Err(io::Error::last_os_error());
            }
            let deadline = Instant::now() + CLEANUP_TIMEOUT;
            loop {
                if self.active_processes_with(&query)? == 0 {
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Windows agent job did not become empty within 2 seconds",
                    ));
                }
                thread::sleep(Duration::from_millis(10));
            }
        }

        /// How many processes the job still holds, over the Win32 call that
        /// answers.
        ///
        /// R22's release is "released on exit, timeout kill, cancel, or
        /// shutdown (private Job Object / process group)", and this is the only
        /// thing that reports whether the release happened. A query error read
        /// as "empty" would report a job settled while it still held a live
        /// member, so the error branch is the accounting, not an aside — and it
        /// is unreachable without a seam.
        pub(super) fn active_processes_with(
            &self,
            query: impl Fn(HANDLE, &mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION) -> i32,
        ) -> io::Result<u32> {
            let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
            if query(self.handle, &mut accounting) == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(accounting.ActiveProcesses)
        }

        /// Whether `pid` is a member of **this** job, asked of the kernel.
        ///
        /// The Windows counterpart of `child_leads_its_own_group`, and
        /// test-only for the same reason: an independent oracle for the
        /// private job's identity, not a production guard. `IsProcessInJob`
        /// answers from the process table, so it cannot agree with a spawn path
        /// that never assigned anything.
        #[cfg(test)]
        pub(super) fn contains(&self, pid: u32) -> Option<bool> {
            job_contains(self.handle, pid)
        }
    }

    impl Drop for Job {
        fn drop(&mut self) {
            // SAFETY: this object uniquely owns the non-inheritable handle.
            // KILL_ON_JOB_CLOSE is the final fail-safe if explicit settlement
            // returned an error or the conductor is being torn down.
            let _ = unsafe { CloseHandle(self.handle) };
        }
    }

    pub(super) fn spawn_suspended_in_job(
        command: &mut Command,
        hooks: &mut dyn SpawnHooks,
    ) -> io::Result<(Child, Job)> {
        spawn_suspended_in_job_with(command, hooks, real_assign_to_job, resume_only_thread)
    }

    /// The real `AssignProcessToJobObject`, as [`spawn_suspended_in_job`]
    /// passes it.
    pub(super) fn real_assign_to_job(job: HANDLE, process: HANDLE) -> i32 {
        // SAFETY: `Child` owns a live process handle and `job` is live; both
        // are process-wide kernel object references, not borrowed memory.
        unsafe { AssignProcessToJobObject(job, process) }
    }

    /// Whether `pid` is a member of the job `job`, asked of the kernel.
    ///
    /// See [`Job::contains`]; this is the same query for a handle a test
    /// captured through the assignment seam rather than for a live [`Job`],
    /// because constructing a second `Job` over the same handle would close it
    /// on drop.
    #[cfg(test)]
    pub(super) fn job_contains(job: HANDLE, pid: u32) -> Option<bool> {
        let process = OpenHandle::open(pid)?;
        let mut member = 0;
        // SAFETY: both handles are live and `member` is a writable BOOL.
        let queried = unsafe { IsProcessInJob(process.0, job, &raw mut member) };
        if queried == 0 {
            return None;
        }
        Some(member != 0)
    }

    /// [`spawn_suspended_in_job`] over the two Win32 steps that come after
    /// creation.
    ///
    /// Both always succeed on a working machine, so the two cleanup branches
    /// that follow them — terminate the private job, kill the child, wait for
    /// it — are unreachable in every real test, and R22's "created as an
    /// ambient-job member, so a coordinator death at any spawn sub-step incl.
    /// the create-suspended prefix terminates it" was asserted for the ambient
    /// job and not for the spawn path's own recovery.
    ///
    /// `assign` is also what makes the `PrivateJobAssigned` coordinate
    /// checkable: it hands a test the private job's handle at the instant the
    /// assignment is made, so the hook can be measured against the operation it
    /// is named for rather than against the other hooks.
    pub(super) fn spawn_suspended_in_job_with(
        command: &mut Command,
        hooks: &mut dyn SpawnHooks,
        assign: impl FnOnce(HANDLE, HANDLE) -> i32,
        resume: impl FnOnce(u32) -> io::Result<()>,
    ) -> io::Result<(Child, Job)> {
        let job = Job::create()?;
        command.creation_flags(CREATE_SUSPENDED);
        let mut child = command.spawn()?;
        hooks.child_created(child.id());
        // `Spawn.CreatedSuspended`: "the child is already an ambient-job
        // member". This is the window the ambient job exists to close -- a
        // coordinator killed here leaves a suspended process that no private
        // job owns -- so it is where the kill injection goes.
        if let Err(error) = apply_io(
            hooks.point(SubEffectPoint::CreatedSuspended),
            SubEffectPoint::CreatedSuspended,
        ) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        // The primary thread is still suspended, so candidate code cannot
        // create an escaping child between process creation and assignment to
        // the job.
        let assigned = assign(job.handle, child.as_raw_handle() as HANDLE);
        if assigned == 0 {
            let error = io::Error::last_os_error();
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        if let Err(error) = apply_io(
            hooks.point(SubEffectPoint::PrivateJobAssigned),
            SubEffectPoint::PrivateJobAssigned,
        ) {
            let _ = job.terminate_and_wait();
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        if let Err(error) = resume(child.id()) {
            let _ = job.terminate_and_wait();
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        if let Err(error) = apply_io(
            hooks.point(SubEffectPoint::Resumed),
            SubEffectPoint::Resumed,
        ) {
            let _ = job.terminate_and_wait();
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        Ok((child, job))
    }

    /// The coordinator's ambient kill-on-close Job Object.
    ///
    /// A process-wide singleton, and never dropped: `OnceLock` in a `static`
    /// has no destructor, so the handle survives to process exit. That is the
    /// requirement, not an accident -- the coordinator is itself a member, so
    /// closing this handle terminates the coordinator.
    static AMBIENT: OnceLock<Result<AmbientJob, String>> = OnceLock::new();

    /// The ambient job's handle, held for the life of the process.
    ///
    /// A separate type from [`Job`] and not merely a second value of it,
    /// because the two have opposite ownership rules. `Job` is owned by the
    /// thread supervising one invocation and its `Drop` is load-bearing --
    /// closing it is how a timeout settles the tree. This one is shared by
    /// every thread and must never be closed, so it has no `Drop` at all.
    #[derive(Debug)]
    struct AmbientJob(HANDLE);

    // SAFETY: a Windows `HANDLE` is a process-wide reference to a kernel
    // object, not a pointer into this process's memory. The only calls made on
    // this one -- `AssignProcessToJobObject` and `IsProcessInJob` -- are
    // thread-safe, the value is never mutated after the `OnceLock` is set, and
    // it is never closed.
    unsafe impl Send for AmbientJob {}
    // SAFETY: as above.
    unsafe impl Sync for AmbientJob {}

    /// Create the ambient job and put this process in it, once.
    ///
    /// The memo is decided by [`super::memoised_outcome`] rather than by a
    /// `match` here, because that arm is unreachable in this process once
    /// either answer has been taken. See its documentation.
    pub(super) fn join_ambient() -> Result<(), String> {
        super::memoised_outcome(AMBIENT.get_or_init(|| {
            // SAFETY: `GetCurrentProcess` is the documented pseudo-handle for
            // this process and the job handle is live. Windows 8 and later
            // nest jobs, so an existing job (cargo's, a CI runner's, an
            // OpenSSH session's) is a parent of this one rather than a
            // conflict.
            create_ambient(|job, process| unsafe { AssignProcessToJobObject(job, process) })
        }))
    }

    /// Memoise an ambient **failure** before anything has joined, so a test
    /// process can carry a real one through [`join_ambient`].
    ///
    /// Spends the process's one ambient cell, so it belongs only in a
    /// subprocess helper. Returns whether the cell was still free.
    #[cfg(test)]
    pub(super) fn poison_ambient_for_tests(message: &str) -> bool {
        AMBIENT.set(Err(message.to_owned())).is_ok()
    }

    /// The body of [`join_ambient`], over the assignment call it makes.
    ///
    /// `assign` is a parameter for one reason: `AssignProcessToJobObject`
    /// returns a Win32 `BOOL`, where **zero is failure and every other value
    /// — including `-1` — is success**, and on a working machine it always
    /// returns success. So the branch that reads it is unreachable in every
    /// real test, and `if joined == 0` could be `if joined == -1` with the
    /// whole suite green while `crash_reconstruction`'s "if the ambient job
    /// cannot be created or joined the write command refuses at startup"
    /// silently stopped holding.
    ///
    /// Not memoised, and it does not touch [`AMBIENT`]: a test may call this
    /// with a refusing `assign` without spending the process's one ambient
    /// job.
    fn create_ambient(assign: impl Fn(HANDLE, HANDLE) -> i32) -> Result<AmbientJob, String> {
        create_ambient_with(Job::create, assign)
    }

    /// [`create_ambient`] over the job it creates as well as the assignment.
    ///
    /// `crash_reconstruction` names two failures and this slice's contract
    /// names them together — "ambient job cannot be **created** or joined
    /// (Windows) → write command refuses at startup with a diagnostic". The
    /// join half had a seam and the creation half did not, so the branch that
    /// turns a failed `CreateJobObjectW` or `SetInformationJobObject` into a
    /// refusal was unreachable: `create_ambient` could have returned a disabled
    /// job and continued, and the whole suite would have stayed green while the
    /// coordinator ran with no ambient job at all.
    fn create_ambient_with(
        make_job: impl FnOnce() -> io::Result<Job>,
        assign: impl Fn(HANDLE, HANDLE) -> i32,
    ) -> Result<AmbientJob, String> {
        let job = make_job().map_err(|error| format!("it could not be created ({error})"))?;
        // SAFETY: `GetCurrentProcess` is the documented pseudo-handle for this
        // process and the job handle is live.
        let joined = assign(job.handle, unsafe { GetCurrentProcess() });
        if joined == 0 {
            // `job` drops here, closing the handle: a kill-on-close job
            // with no members terminates nothing.
            return Err(format!(
                "this process could not join it ({})",
                io::Error::last_os_error()
            ));
        }
        // Joined. From here the handle must outlive every `Drop` in this
        // process, because closing it terminates this process.
        let job = std::mem::ManuallyDrop::new(job);
        Ok(AmbientJob(job.handle))
    }

    /// Whether the ambient job has been established in this process.
    pub(super) fn ambient_established() -> bool {
        matches!(AMBIENT.get(), Some(Ok(_)))
    }

    /// Whether `pid` is a member of this process's ambient job.
    ///
    /// `None` when no ambient job has been established, or the process cannot
    /// be opened. The kernel answers, so this is an oracle independent of the
    /// spawn path it checks.
    pub(super) fn ambient_contains(pid: u32) -> Option<bool> {
        let Some(Ok(job)) = AMBIENT.get() else {
            return None;
        };
        let process = OpenHandle::open(pid)?;
        let mut member = 0;
        // SAFETY: both handles are live and `member` is a writable BOOL.
        let queried = unsafe { IsProcessInJob(process.0, job.0, &raw mut member) };
        if queried == 0 {
            return None;
        }
        Some(member != 0)
    }

    /// A borrowed process handle with query and synchronise rights.
    struct OpenHandle(HANDLE);

    impl OpenHandle {
        fn open(pid: u32) -> Option<Self> {
            // SAFETY: no borrowed inputs; a failure returns null.
            let handle =
                unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid) };
            if handle.is_null() {
                return None;
            }
            Some(Self(handle))
        }
    }

    impl Drop for OpenHandle {
        fn drop(&mut self) {
            // SAFETY: this wrapper uniquely owns the handle it opened.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }

    fn creation_time(handle: HANDLE) -> Option<u64> {
        let mut created = FILETIME::default();
        let mut exited = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: four correctly typed writable output structures and a live
        // handle with PROCESS_QUERY_LIMITED_INFORMATION.
        let queried = unsafe {
            GetProcessTimes(
                handle,
                &raw mut created,
                &raw mut exited,
                &raw mut kernel,
                &raw mut user,
            )
        };
        if queried == 0 {
            return None;
        }
        Some((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
    }

    pub(super) fn process_creation_time(pid: u32) -> Option<u64> {
        let handle = OpenHandle::open(pid)?;
        creation_time(handle.0)
    }

    pub(super) fn process_alive(pid: u32, expected_creation_time: u64) -> bool {
        let Some(handle) = OpenHandle::open(pid) else {
            return false;
        };
        if creation_time(handle.0) != Some(expected_creation_time) {
            // The pid was reused: whatever is running under it now is not the
            // process the caller asked about.
            return false;
        }
        // SAFETY: the handle carries SYNCHRONIZE. A process object is signaled
        // exactly when the process has terminated, which is a stronger answer
        // than an exit code a job termination chooses for us.
        unsafe { WaitForSingleObject(handle.0, 0) == WAIT_TIMEOUT }
    }

    pub(super) fn resume_only_thread(process_id: u32) -> io::Result<()> {
        let thread_handle = primary_thread(process_id)?;
        // SAFETY: this handle has THREAD_SUSPEND_RESUME access and identifies
        // the primary thread created suspended by `Command::spawn`.
        if unsafe { ResumeThread(thread_handle.0) } == u32::MAX {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// How many outstanding suspends the child's primary thread carries.
    ///
    /// The Windows counterpart of `child_leads_its_own_group`: an oracle for
    /// "is this child still suspended" that asks the kernel rather than the
    /// crate, so the `CreatedSuspended`, `PrivateJobAssigned` and `Resumed`
    /// coordinates can be measured against the operations they name instead of
    /// against each other. `SuspendThread` returns the count *before* its own
    /// increment and the matching `ResumeThread` puts it back, so the
    /// observation leaves the child exactly as it found it.
    ///
    /// Test-only, like the Unix one and for the same reason: as a production
    /// guard it could only ever withhold a point it cannot add information to.
    #[cfg(test)]
    pub(super) fn primary_thread_suspend_count(process_id: u32) -> io::Result<u32> {
        use windows_sys::Win32::System::Threading::SuspendThread;

        let thread_handle = primary_thread(process_id)?;
        // SAFETY: the handle carries THREAD_SUSPEND_RESUME and names a live
        // thread; the immediately following resume restores the count.
        let previous = unsafe { SuspendThread(thread_handle.0) };
        if previous == u32::MAX {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: as above; this undoes the suspend just taken.
        if unsafe { ResumeThread(thread_handle.0) } == u32::MAX {
            return Err(io::Error::last_os_error());
        }
        Ok(previous)
    }

    /// A suspend/resume handle on `process_id`'s primary thread.
    fn primary_thread(process_id: u32) -> io::Result<Snapshot> {
        // CREATE_SUSPENDED prevents the process from creating another thread,
        // so the one owned thread in this system snapshot is necessarily its
        // primary thread.
        // SAFETY: the snapshot call has no borrowed inputs.
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let snapshot = Snapshot(snapshot);
        let mut entry = THREADENTRY32 {
            dwSize: u32::try_from(size_of::<THREADENTRY32>())
                .expect("thread entry structure fits in u32"),
            ..THREADENTRY32::default()
        };
        // SAFETY: `entry` advertises its correct size and remains writable.
        if unsafe { Thread32First(snapshot.0, &mut entry) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let thread_id = loop {
            if entry.th32OwnerProcessID == process_id {
                break entry.th32ThreadID;
            }
            // SAFETY: same valid snapshot and output entry as above.
            if unsafe { Thread32Next(snapshot.0, &mut entry) } == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "could not find the suspended agent primary thread",
                ));
            }
        };
        // SAFETY: the enumerated thread id belongs to the still-suspended
        // child; the returned handle is non-inheritable.
        let thread_handle = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, thread_id) };
        if thread_handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Snapshot(thread_handle))
    }

    struct Snapshot(HANDLE);

    impl Drop for Snapshot {
        fn drop(&mut self) {
            // SAFETY: this wrapper uniquely owns its snapshot/thread handle.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// `AssignProcessToJobObject` answers with a Win32 `BOOL`: **zero is
        /// failure and every other value is success**, `-1` included.
        ///
        /// Every real assignment on a working machine succeeds, so the branch
        /// that reads this value is unreachable in an ordinary test and
        /// `if joined == 0` could become `if joined == -1` with the suite
        /// green — while an actual refusal (an outer job with UI restrictions,
        /// a job the process may not join) was read as success and startup
        /// returned `Ok` holding an ambient job with no members. The
        /// coordinator would then take workspace effects and spawn children
        /// that no ambient job owns, which is the whole of INV-18's host
        /// portion.
        ///
        /// The expected mapping is Win32's, written here, not read from the
        /// code under test.
        #[test]
        fn the_ambient_join_reads_a_win32_bool_the_way_win32_defines_one() {
            let refused =
                create_ambient(|_, _| 0).expect_err("a zero BOOL is a refused assignment");
            assert!(
                refused.contains("could not join"),
                "the diagnostic must name the join: {refused}"
            );

            // Every other value is success. Each of these creates a real job
            // object this process is deliberately *not* a member of; the
            // handle is left open exactly as the real ambient one is, and a
            // kill-on-close job with no members terminates nothing.
            for value in [1_i32, -1, i32::MIN, i32::MAX] {
                let job = create_ambient(move |_, _| value)
                    .unwrap_or_else(|error| panic!("BOOL {value} is success, not: {error}"));
                assert!(!job.0.is_null(), "BOOL {value} produced no job handle");
            }
        }

        /// The other two thirds of the sentence the join test covers.
        ///
        /// `expected_failures_refusals[1]` is "ambient job cannot be
        /// **created** or joined (Windows) → write command refuses at startup
        /// with a diagnostic", and INV-18's host portion is "refusal before any
        /// effect if the ambient job cannot be **established**". Establishing
        /// is three Win32 calls, not one: `CreateJobObjectW`,
        /// `SetInformationJobObject`, `AssignProcessToJobObject`. Only the last
        /// had a seam, so the first two could each have been ignored — an
        /// ambient job that was never created, or one created without
        /// `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and therefore with no fail-safe
        /// at all — with the suite green.
        ///
        /// Both failures are unreachable on a working machine, which is why
        /// they need the seam rather than a fixture.
        #[test]
        fn the_ambient_job_refuses_when_it_cannot_be_created_or_configured() {
            use std::cell::Cell;

            // A job that cannot be created is not configured and not joined.
            let configured = Cell::new(false);
            let refused = create_ambient_with(
                || {
                    Job::create_with(ptr::null_mut, |_, _, _| {
                        configured.set(true);
                        1
                    })
                },
                |_, _| panic!("a job that was never created must not be joined"),
            )
            .expect_err("a job that cannot be created is not an ambient job");
            assert!(
                !configured.get(),
                "an uncreated job was handed to SetInformationJobObject"
            );
            assert!(
                refused.contains("could not be created"),
                "the diagnostic must name creation: {refused}"
            );

            // A job that cannot be configured is refused, not kept: without
            // KILL_ON_JOB_CLOSE the ambient job terminates nothing on
            // coordinator death, which is the whole of INV-18's host portion.
            let refused = create_ambient_with(
                || Job::create_with(real_create_job, |_, _, _| 0),
                |_, _| panic!("an unconfigured job must not be joined"),
            )
            .expect_err("an unconfigured job is not an ambient job");
            assert!(
                refused.contains("could not be created"),
                "the diagnostic must name establishment: {refused}"
            );
        }

        /// What `SetInformationJobObject` is actually asked for.
        ///
        /// `KILL_ON_JOB_CLOSE` is the mechanism DESIGN.md:402 names — "abrupt
        /// conductor death closes its non-inheritable handle and lets the
        /// kernel terminate ordinary descendants" — and a job configured with
        /// any other limit flag would still return success. The expected flag
        /// and the expected structure size are Win32's, written here rather
        /// than read back from the call under test.
        #[test]
        fn every_job_this_module_creates_is_configured_to_kill_on_close() {
            use std::cell::Cell;

            let seen = Cell::new(None);
            let job = Job::create_with(real_create_job, |handle, limits, size| {
                seen.set(Some((limits.BasicLimitInformation.LimitFlags, size)));
                real_configure_job(handle, limits, size)
            })
            .expect("create a job the ordinary way");
            assert!(!job.handle.is_null());
            let (flags, size) = seen.get().expect("the configuration call was made");
            assert_eq!(
                flags, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                "the kill-on-close fail-safe is the limit this job exists for"
            );
            assert_eq!(
                size,
                u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()).expect("fits"),
                "the extended limit structure is declared at its own size"
            );
        }

        /// An accounting error is an error, never an empty job.
        ///
        /// R22 releases the host process "on exit, timeout kill, cancel, or
        /// shutdown (private Job Object / process group)", and
        /// `QueryInformationJobObject` is the only thing that reports whether
        /// that release happened. Reading a failed query as zero would report a
        /// job settled while it still held a live member — the accounting
        /// saying "released" over a resource that is not.
        #[test]
        fn a_failed_accounting_query_is_never_read_as_an_empty_job() {
            let job = Job::create().expect("create a job");
            let error = job
                .active_processes_with(|_, _| 0)
                .expect_err("a zero BOOL from QueryInformationJobObject is a failure");
            assert!(
                !format!("{error}").is_empty(),
                "the OS's reason must survive"
            );
            // And a query that answers is believed, whatever it answers.
            for reported in [0_u32, 1, 7] {
                let observed = job
                    .active_processes_with(move |_, accounting| {
                        accounting.ActiveProcesses = reported;
                        1
                    })
                    .expect("a successful query is not an error");
                assert_eq!(observed, reported);
            }
        }

        /// Cleanup **observes** the job empty; it does not assume it.
        ///
        /// DESIGN.md:402 — "Direct-child success and timeout both terminate and
        /// boundedly observe that job empty". A real job empties by the first
        /// query, so an implementation that skipped the loop entirely is
        /// indistinguishable from this one on any real tree. The accounting
        /// responses here are chosen, not observed: 1, 1, 0.
        #[test]
        fn cleanup_polls_the_accounting_until_the_job_is_empty() {
            use std::cell::Cell;

            let job = Job::create().expect("create a job");
            let terminated = Cell::new(false);
            let answers = Cell::new(0_usize);
            job.terminate_and_wait_with(
                |_| {
                    terminated.set(true);
                    1
                },
                |_, accounting| {
                    let index = answers.get();
                    answers.set(index + 1);
                    accounting.ActiveProcesses = if index < 2 { 1 } else { 0 };
                    1
                },
            )
            .expect("cleanup completes once the job reports empty");
            assert!(terminated.get(), "the job was never terminated");
            assert_eq!(
                answers.get(),
                3,
                "cleanup returned before the accounting said zero, or kept asking after it did"
            );
        }

        /// And the observation is **bounded**.
        ///
        /// A job that never reports empty must produce a diagnostic within the
        /// documented two seconds rather than pinning a supervisor thread for
        /// the life of the process. The bound is asserted from outside, on a
        /// worker thread, so an unbounded loop fails this test with a named
        /// message instead of hanging the whole binary.
        #[test]
        fn cleanup_gives_up_on_a_job_that_never_empties() {
            use std::sync::mpsc;

            let (sender, receiver) = mpsc::channel();
            thread::spawn(move || {
                let job = Job::create().expect("create a job");
                let outcome = job
                    .terminate_and_wait_with(
                        |_| 1,
                        |_, accounting| {
                            accounting.ActiveProcesses = 1;
                            1
                        },
                    )
                    .map_err(|error| (error.kind(), error.to_string()));
                let _ = sender.send(outcome);
            });
            let outcome = receiver
                .recv_timeout(Duration::from_secs(30))
                .expect("cleanup must be bounded: it never returned");
            let (kind, message) = outcome.expect_err("a job that never empties is not settled");
            assert_eq!(kind, io::ErrorKind::TimedOut, "{message}");
            assert!(
                message.contains("2 seconds"),
                "the diagnostic must name its bound: {message}"
            );
        }
    }
}

#[cfg(unix)]
fn child_exited_unreaped(child: &Child) -> std::io::Result<bool> {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let pid = libc::id_t::try_from(child.id())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            pid,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { info.si_pid() } == 0 {
        return Ok(false);
    }
    // WEXITED should filter non-terminal transitions, but Darwin can leave a
    // stopped/continued record observable around job-control delivery. Never
    // turn such a record into permission for the reaper to SIGKILL the group.
    Ok(matches!(
        info.si_code,
        libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED
    ))
}

/// Process-wide Unix termination coordination.
///
/// A signal handler may only perform async-signal-safe work. It therefore
/// stores the first terminating signal in an atomic and returns. A detached
/// monitor thread owns the locks, termination, and job-control forwarding,
/// then restores the default disposition and re-raises a terminating signal.
/// `spawning` closes the otherwise unavoidable race between `Command::spawn`
/// and pid registration; the monitor cannot terminate or suspend the parent
/// while it is nonzero.
#[cfg(unix)]
mod termination {
    use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};
    use std::thread;
    use std::time::Duration;

    use crate::error::TactusError;

    static PENDING_TERMINATION: AtomicI32 = AtomicI32::new(0);
    static SUSPEND_REQUESTED: AtomicBool = AtomicBool::new(false);
    static CONTINUE_REQUESTED: AtomicBool = AtomicBool::new(false);
    static SUSPEND_ARMED: AtomicBool = AtomicBool::new(false);
    static GUARD_COMMAND_FD: AtomicI32 = AtomicI32::new(-1);
    static GUARD_WAKE_FD: AtomicI32 = AtomicI32::new(-1);
    static PROBE_PID: AtomicI32 = AtomicI32::new(-1);
    static HANDLED_TERMINATION_MASK: AtomicU8 = AtomicU8::new(0);
    static STATE: OnceLock<Result<Arc<Mutex<State>>, String>> = OnceLock::new();

    const GUARD_READY: u8 = 0x91;
    const GUARD_ARM: u8 = 0xa1;
    const GUARD_STOP: u8 = 0xb1;
    const GUARD_STOPPED: u8 = 0xb2;
    const GUARD_CANCELLED: u8 = 0xc1;
    const GUARD_DISARM: u8 = 0xd1;
    const GUARD_PROBE: u8 = 0xe1;
    const HANDLE_SIGINT: u8 = 1 << 0;
    const HANDLE_SIGTERM: u8 = 1 << 1;
    const HANDLE_SIGHUP: u8 = 1 << 2;
    const HANDLE_SIGQUIT: u8 = 1 << 3;
    const HANDLE_SIGTSTP: u8 = 1 << 0;
    const HANDLE_SIGTTIN: u8 = 1 << 1;
    const HANDLE_SIGTTOU: u8 = 1 << 2;
    const REAPER_READY: u8 = 0x81;
    const REAPER_REGISTER: u8 = 0x82;
    const REAPER_CLEANUP: u8 = 0x83;
    const REAPER_OK: u8 = 0x84;
    const REAPER_FAIL: u8 = 0x85;
    const REAPER_CANCEL: u8 = 0x86;
    // The job-control guard briefly continues only Tactus every 250 ms while
    // probing for a PID-directed termination. The cleanup reaper must not
    // mistake that internal pulse for an operator resume and continue agents.
    // Genuine SIGCONT is forwarded immediately by the monitor; this bounded
    // fallback exists for host-owned signal policies the monitor preserves.
    const REAPER_RESUME_STABLE_POLLS: u8 = 50;

    #[derive(Clone, Copy)]
    struct SignalPolicy {
        termination_mask: u8,
        guard_wake_mask: u8,
        stop_mask: u8,
        job_control: bool,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum SignalDisposition {
        Default,
        Ignored,
        Custom,
    }

    impl SignalPolicy {
        fn handles_termination(self, signal: libc::c_int) -> bool {
            let bit = match signal {
                libc::SIGINT => HANDLE_SIGINT,
                libc::SIGTERM => HANDLE_SIGTERM,
                libc::SIGHUP => HANDLE_SIGHUP,
                libc::SIGQUIT => HANDLE_SIGQUIT,
                _ => return false,
            };
            self.termination_mask & bit != 0
        }

        fn wakes_guard(self, signal: libc::c_int) -> bool {
            let bit = match signal {
                libc::SIGINT => HANDLE_SIGINT,
                libc::SIGTERM => HANDLE_SIGTERM,
                libc::SIGHUP => HANDLE_SIGHUP,
                libc::SIGQUIT => HANDLE_SIGQUIT,
                _ => return false,
            };
            self.guard_wake_mask & bit != 0
        }

        fn handles_stop(self, signal: libc::c_int) -> bool {
            let bit = match signal {
                libc::SIGTSTP => HANDLE_SIGTSTP,
                libc::SIGTTIN => HANDLE_SIGTTIN,
                libc::SIGTTOU => HANDLE_SIGTTOU,
                _ => return false,
            };
            self.stop_mask & bit != 0
        }
    }

    struct State {
        /// Supervisors that entered before spawn but have not registered a pid.
        spawning: usize,
        /// Active isolated process groups. A signal lease pins the numeric
        /// identity until the monitor has delivered its snapshot's signal, so
        /// `finish` cannot reap the leader and expose that id for reuse first.
        groups: Vec<RegisteredGroup>,
        /// Set by the monitor before it kills groups. No later spawn may begin.
        terminating: bool,
        /// Set before a suspend snapshot and cleared only after continuation.
        /// New launches wait outside the lock for the complete transition.
        suspending: bool,
        guard: Guard,
    }

    struct RegisteredGroup {
        pgid: i32,
        signal_leases: usize,
    }

    struct GroupSnapshot {
        state: Arc<Mutex<State>>,
        pgids: Vec<i32>,
    }

    impl std::ops::Deref for GroupSnapshot {
        type Target = [i32];

        fn deref(&self) -> &Self::Target {
            &self.pgids
        }
    }

    impl Drop for GroupSnapshot {
        fn drop(&mut self) {
            let mut locked = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for pgid in &self.pgids {
                if let Some(group) = locked.groups.iter_mut().find(|group| group.pgid == *pgid) {
                    group.signal_leases = group.signal_leases.saturating_sub(1);
                }
            }
        }
    }

    #[derive(Clone, Copy)]
    struct Reaper {
        command_fd: libc::c_int,
        ack_fd: libc::c_int,
        _command_keepalive_fd: libc::c_int,
        pid: libc::pid_t,
    }

    #[derive(Clone, Copy)]
    struct Guard {
        command_fd: libc::c_int,
        ack_fd: libc::c_int,
        // Keep one parent-side reader open so a guard crash turns the next arm
        // into an acknowledgement EOF instead of delivering SIGPIPE from an
        // async signal handler that writes the command pipe.
        _command_keepalive_fd: libc::c_int,
        pid: libc::pid_t,
    }

    enum Phase {
        Spawning,
        Group(i32),
        Finished,
    }

    pub(super) struct Supervisor {
        state: Arc<Mutex<State>>,
        phase: Phase,
        reaper: Reaper,
    }

    impl Supervisor {
        pub(super) fn begin() -> Result<Self, TactusError> {
            Self::begin_with_state(shared_state()?)
        }

        fn begin_with_state(state: Arc<Mutex<State>>) -> Result<Self, TactusError> {
            claim_launch(&state)?;
            let reaper = match spawn_reaper() {
                Ok(reaper) => reaper,
                Err(message) => {
                    release_launch(&state);
                    return Err(TactusError::Agent { message });
                }
            };
            Ok(Self {
                state,
                phase: Phase::Spawning,
                reaper,
            })
        }

        pub(super) fn prepare(&self, command: &mut std::process::Command) {
            use std::os::unix::process::CommandExt;

            let reaper = self.reaper;
            // SAFETY: the closure uses only async-signal-safe syscalls. It
            // creates the private process group and registers it with the
            // external reaper before exec, so even SIGKILL in the parent's
            // post-spawn registration window cannot orphan the agent tree.
            unsafe {
                command.pre_exec(move || {
                    let pid = libc::getpid();
                    if libc::setpgid(0, 0) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if reaper.register_raw(pid) {
                        Ok(())
                    } else {
                        Err(std::io::Error::from_raw_os_error(libc::EIO))
                    }
                });
            }
        }

        pub(super) fn register(&mut self, pid: u32) -> Result<(), TactusError> {
            let pgid = i32::try_from(pid).map_err(|_| TactusError::Agent {
                message: format!("agent pid {pid} cannot be represented as a Unix process group"),
            })?;
            let mut locked = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            locked.spawning = locked.spawning.saturating_sub(1);
            locked.groups.push(RegisteredGroup {
                pgid,
                signal_leases: 0,
            });
            self.phase = Phase::Group(pgid);
            Ok(())
        }

        pub(super) fn finish(&mut self) -> Result<(), TactusError> {
            let Phase::Group(pgid) = self.phase else {
                return Ok(());
            };
            // `cleanup` consumes and closes the reaper's raw descriptors.
            // Change phase first so an error return followed by Drop can never
            // transact on—or close—descriptor numbers another thread may
            // already have reused.
            self.phase = Phase::Finished;
            if !self.reaper.cleanup(pgid) {
                let _ = PENDING_TERMINATION.compare_exchange(
                    0,
                    libc::SIGTERM,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
                return Err(TactusError::Agent {
                    message: format!(
                        "Unix cleanup reaper failed while settling process group {pgid}"
                    ),
                });
            }
            loop {
                let mut locked = self
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if !locked.groups.iter().any(|group| group.pgid == pgid) {
                    return Ok(());
                }
                if remove_unpinned_group(&mut locked, pgid) {
                    return Ok(());
                }
                drop(locked);
                thread::sleep(Duration::from_millis(1));
            }
        }
    }

    fn claim_launch(state: &Arc<Mutex<State>>) -> Result<(), TactusError> {
        loop {
            let mut locked = state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if locked.terminating || PENDING_TERMINATION.load(Ordering::SeqCst) != 0 {
                return Err(TactusError::Agent {
                    message: "process launch interrupted by a termination signal".to_owned(),
                });
            }
            if !locked.suspending && locked.spawning == 0 {
                locked.spawning = locked.spawning.saturating_add(1);
                return Ok(());
            }
            drop(locked);
            thread::sleep(Duration::from_millis(1));
        }
    }

    /// The process groups the parent supervisor currently has registered.
    ///
    /// Test-only, and an oracle rather than a guard: `Spawn.Registered` is
    /// "parent-side registration", and the only way to ask whether that
    /// happened before the point fired is to read the state it writes.
    #[cfg(test)]
    pub(super) fn registered_groups() -> Vec<i32> {
        let Ok(state) = shared_state() else {
            return Vec::new();
        };
        let locked = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        locked.groups.iter().map(|group| group.pgid).collect()
    }

    fn release_launch(state: &Arc<Mutex<State>>) {
        let mut locked = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        locked.spawning = locked.spawning.saturating_sub(1);
    }

    impl Drop for Supervisor {
        fn drop(&mut self) {
            match self.phase {
                Phase::Spawning => {
                    self.reaper.cancel();
                    release_launch(&self.state);
                }
                Phase::Group(_) => {
                    // `finish` normally runs while the direct child is still
                    // an unreaped zombie, pinning the process-group identity.
                    // Error unwinding remains fail-closed through the same
                    // external reaper rather than trusting a recycled PGID;
                    // a failure consumes the reaper and arms process exit.
                    let _ = self.finish();
                }
                Phase::Finished => {}
            }
        }
    }

    fn shared_state() -> Result<Arc<Mutex<State>>, TactusError> {
        match STATE.get_or_init(install) {
            Ok(state) => Ok(Arc::clone(state)),
            Err(message) => Err(TactusError::Agent {
                message: message.clone(),
            }),
        }
    }

    fn install() -> Result<Arc<Mutex<State>>, String> {
        let mut policy = SignalPolicy {
            termination_mask: 0,
            guard_wake_mask: 0,
            stop_mask: 0,
            job_control: false,
        };
        for (signal, bit) in [
            (libc::SIGINT, HANDLE_SIGINT),
            (libc::SIGTERM, HANDLE_SIGTERM),
            (libc::SIGHUP, HANDLE_SIGHUP),
            (libc::SIGQUIT, HANDLE_SIGQUIT),
        ] {
            match disposition(signal)? {
                SignalDisposition::Default => {
                    policy.termination_mask |= bit;
                    policy.guard_wake_mask |= bit;
                }
                SignalDisposition::Custom => policy.guard_wake_mask |= bit,
                SignalDisposition::Ignored => {}
            }
        }
        for (signal, bit) in [
            (libc::SIGTSTP, HANDLE_SIGTSTP),
            (libc::SIGTTIN, HANDLE_SIGTTIN),
            (libc::SIGTTOU, HANDLE_SIGTTOU),
        ] {
            if disposition(signal)? == SignalDisposition::Default {
                policy.stop_mask |= bit;
            }
        }
        let continue_disposition = disposition(libc::SIGCONT)?;
        if policy.stop_mask != 0 && continue_disposition != SignalDisposition::Default {
            return Err(
                "cannot safely proxy default Unix job-control stops while the embedding host owns or ignores SIGCONT"
                    .to_owned(),
            );
        }
        policy.job_control = policy.stop_mask != 0;
        HANDLED_TERMINATION_MASK.store(policy.termination_mask, Ordering::SeqCst);

        let guard = spawn_guard(policy)?;
        let state = Arc::new(Mutex::new(State {
            spawning: 0,
            groups: Vec::new(),
            terminating: false,
            suspending: false,
            guard,
        }));
        let monitored = Arc::clone(&state);
        let (monitor_ready, monitor_started) = std::sync::mpsc::sync_channel(1);
        let monitor = thread::Builder::new()
            .name("tactus-signal-monitor".to_owned())
            .spawn(move || match prepare_monitor_signal_mask(policy) {
                Ok(()) => {
                    let _ = monitor_ready.send(Ok(()));
                    monitor(monitored)
                }
                Err(error) => {
                    let _ = monitor_ready.send(Err(error));
                }
            });
        let monitor = match monitor {
            Ok(monitor) => monitor,
            Err(error) => {
                guard.abort_setup();
                return Err(format!("starting Unix signal monitor: {error}"));
            }
        };
        match monitor_started.recv() {
            Ok(Ok(())) => drop(monitor),
            Ok(Err(error)) => {
                let _ = monitor.join();
                guard.abort_setup();
                return Err(error);
            }
            Err(error) => {
                let _ = monitor.join();
                guard.abort_setup();
                return Err(format!(
                    "starting Unix signal monitor: readiness channel closed: {error}"
                ));
            }
        }

        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
            // Preserve every launcher-owned policy. POSIX carries SIG_IGN
            // across exec (`nohup` relies on it), while an embedding host may
            // have installed a custom in-process handler before calling us.
            if policy.handles_termination(signal) {
                install_handler(signal)?;
            }
        }

        // Preserve every host-owned stop disposition. Each remaining default
        // terminal stop is proxied, and the policy check above guarantees the
        // matching default SIGCONT can release the isolated groups again.
        if policy.job_control {
            for signal in [libc::SIGTSTP, libc::SIGTTIN, libc::SIGTTOU] {
                if policy.handles_stop(signal) {
                    install_handler(signal)?;
                }
            }
            install_handler(libc::SIGCONT)?;
        }
        Ok(state)
    }

    fn disposition(signal: libc::c_int) -> Result<SignalDisposition, String> {
        // SAFETY: a null `act` queries the current disposition without
        // changing it; `previous` is initialized by a successful call.
        unsafe {
            let mut previous: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(signal, std::ptr::null(), &mut previous) != 0 {
                return Err(format!(
                    "reading Unix signal disposition for signal {signal}: {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(if previous.sa_sigaction == libc::SIG_IGN {
                SignalDisposition::Ignored
            } else if previous.sa_sigaction == libc::SIG_DFL {
                SignalDisposition::Default
            } else {
                SignalDisposition::Custom
            })
        }
    }

    fn prepare_monitor_signal_mask(policy: SignalPolicy) -> Result<(), String> {
        if !policy.job_control {
            return Ok(());
        }

        // An embedding host may have blocked SIGCONT on the thread that first
        // called Tactus, and new threads inherit that mask. SIGCONT still wakes
        // a stopped process when blocked, but its handler cannot run, so the
        // isolated agent groups would remain stopped forever. Give only the
        // private monitor thread an unblocked SIGCONT; every host thread keeps
        // its original mask.
        unsafe {
            let mut signals: libc::sigset_t = std::mem::zeroed();
            if libc::sigemptyset(&mut signals) != 0
                || libc::sigaddset(&mut signals, libc::SIGCONT) != 0
            {
                return Err(format!(
                    "building Unix signal-monitor mask: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let result = libc::pthread_sigmask(libc::SIG_UNBLOCK, &signals, std::ptr::null_mut());
            if result != 0 {
                return Err(format!(
                    "unblocking SIGCONT in Unix signal monitor: {}",
                    std::io::Error::from_raw_os_error(result)
                ));
            }
        }
        Ok(())
    }

    fn install_handler(signal: libc::c_int) -> Result<(), String> {
        // SAFETY: `record_signal` has the C ABI and performs only lock-free
        // atomic operations. The empty mask and SA_RESTART keep unrelated
        // syscalls from being exposed to the implementation detail that a
        // monitor thread, rather than the handler, owns process-group work.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            if signal == libc::SIGCONT {
                action.sa_sigaction = record_signal_info as *const () as libc::sighandler_t;
                action.sa_flags = libc::SA_RESTART | libc::SA_SIGINFO;
            } else {
                action.sa_sigaction = record_signal as *const () as libc::sighandler_t;
                action.sa_flags = libc::SA_RESTART;
            }
            libc::sigemptyset(&mut action.sa_mask);
            if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
                return Err(format!(
                    "installing Unix signal forwarding for signal {signal}: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        Ok(())
    }

    extern "C" fn record_signal(signal: libc::c_int) {
        match signal {
            libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU => {
                SUSPEND_REQUESTED.store(true, Ordering::SeqCst)
            }
            libc::SIGCONT => {
                CONTINUE_REQUESTED.store(true, Ordering::SeqCst);
                notify_guard(signal);
            }
            _ => {
                let _ = PENDING_TERMINATION.compare_exchange(
                    0,
                    signal,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
                notify_guard(signal);
            }
        }
    }

    extern "C" fn record_signal_info(
        signal: libc::c_int,
        info: *mut libc::siginfo_t,
        _: *mut libc::c_void,
    ) {
        let is_guard_probe = signal == libc::SIGCONT
            && !info.is_null()
            && unsafe { (*info).si_pid() } == PROBE_PID.load(Ordering::SeqCst);
        if !is_guard_probe {
            record_signal(signal);
            return;
        }

        // A stopped process cannot execute a caught termination handler. The
        // external guard periodically resumes only Tactus so this handler can
        // inspect/deliver a PID-directed pending signal; supervised agent
        // groups remain stopped. With no such signal, stop again from inside
        // the handler before returning to ordinary parent code.
        let already_recorded = PENDING_TERMINATION.load(Ordering::SeqCst);
        if already_recorded != 0 {
            notify_guard(already_recorded);
            return;
        }
        let pending = pending_termination_signal();
        if pending != 0 {
            let _ = PENDING_TERMINATION.compare_exchange(
                0,
                pending,
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
            notify_guard(pending);
            return;
        }
        if unsafe { libc::kill(libc::getpid(), libc::SIGSTOP) } != 0 {
            let _ = PENDING_TERMINATION.compare_exchange(
                0,
                libc::SIGTERM,
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
            notify_guard(libc::SIGTERM);
        }
    }

    fn pending_termination_signal() -> libc::c_int {
        unsafe {
            let mut pending: libc::sigset_t = std::mem::zeroed();
            if libc::sigpending(&mut pending) != 0 {
                return libc::SIGTERM;
            }
            let mask = HANDLED_TERMINATION_MASK.load(Ordering::SeqCst);
            for (signal, bit) in [
                (libc::SIGINT, HANDLE_SIGINT),
                (libc::SIGTERM, HANDLE_SIGTERM),
                (libc::SIGHUP, HANDLE_SIGHUP),
                (libc::SIGQUIT, HANDLE_SIGQUIT),
            ] {
                if mask & bit != 0 && libc::sigismember(&pending, signal) == 1 {
                    return signal;
                }
            }
        }
        0
    }

    extern "C" fn record_guard_signal(signal: libc::c_int) {
        let fd = GUARD_WAKE_FD.load(Ordering::SeqCst);
        if fd < 0 {
            return;
        }
        let byte = u8::try_from(signal).unwrap_or(u8::MAX);
        // SAFETY: the wake descriptor is nonblocking and dedicated to the
        // guard's self-pipe. A full pipe is already readable, so dropping that
        // byte cannot lose the wakeup.
        let _ = unsafe { libc::write(fd, (&byte as *const u8).cast(), 1) };
    }

    fn notify_guard(signal: libc::c_int) {
        if !SUSPEND_ARMED.load(Ordering::SeqCst) {
            return;
        }
        let fd = GUARD_COMMAND_FD.load(Ordering::SeqCst);
        if fd < 0 {
            return;
        }
        let byte = u8::try_from(signal).unwrap_or(u8::MAX);
        // SAFETY: `write` is async-signal-safe, the descriptor is a dedicated
        // pipe, and a one-byte record is atomic. The parent retains a reader so
        // a failed guard cannot turn this write into SIGPIPE.
        let _ = unsafe { libc::write(fd, (&byte as *const u8).cast(), 1) };
    }

    fn monitor(state: Arc<Mutex<State>>) -> ! {
        loop {
            let terminating = PENDING_TERMINATION.load(Ordering::SeqCst);
            if terminating != 0 {
                let Some(groups) = groups_when_registered(&state, true) else {
                    thread::sleep(Duration::from_millis(1));
                    continue;
                };
                signal_groups(&groups, libc::SIGKILL);

                // SAFETY: all isolated children have been synchronously sent
                // SIGKILL. Restore the ordinary terminal semantics and
                // terminate Tactus with the original signal; `_exit` is a
                // defensive fallback if a platform returns from `raise`.
                unsafe {
                    libc::signal(terminating, libc::SIG_DFL);
                    libc::raise(terminating);
                    libc::_exit(128 + terminating);
                }
            }

            if SUSPEND_REQUESTED.swap(false, Ordering::SeqCst) {
                let Some((groups, guard)) = begin_suspend(&state) else {
                    SUSPEND_REQUESTED.store(true, Ordering::SeqCst);
                    thread::sleep(Duration::from_millis(1));
                    continue;
                };
                // SIGSTOP cannot be caught or ignored, so a vendor process
                // cannot keep spending while its visibly foreground Tactus
                // parent is suspended. SIGCONT below releases the same groups.
                if !stop_groups(&groups) {
                    let groups = end_suspend(&state);
                    if PENDING_TERMINATION.load(Ordering::SeqCst) == 0 {
                        signal_groups(&groups, libc::SIGCONT);
                    }
                    continue;
                }

                // The guard remains runnable while Tactus is stopped. It
                // serializes a late continuation/termination with the actual
                // SIGSTOP and acknowledges only after a genuine resume. That
                // closes the final flag-check-to-stop interval.
                SUSPEND_ARMED.store(true, Ordering::SeqCst);
                if !guard.arm() {
                    SUSPEND_ARMED.store(false, Ordering::SeqCst);
                    let _ = end_suspend(&state);
                    let _ = PENDING_TERMINATION.compare_exchange(
                        0,
                        libc::SIGTERM,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    );
                    continue;
                }

                // A terminating signal wins over suspension. Do not stop the
                // parent after its monitor has already been asked to tear down.
                if PENDING_TERMINATION.load(Ordering::SeqCst) != 0 {
                    SUSPEND_ARMED.store(false, Ordering::SeqCst);
                    guard.disarm();
                    let _ = end_suspend(&state);
                    continue;
                }
                if CONTINUE_REQUESTED.swap(false, Ordering::SeqCst) {
                    SUSPEND_ARMED.store(false, Ordering::SeqCst);
                    guard.disarm();
                    let groups = end_suspend(&state);
                    signal_groups(&groups, libc::SIGCONT);
                    continue;
                }

                // The external guard sends SIGSTOP while this monitor is
                // blocked on its acknowledgement pipe. Therefore the next
                // instruction cannot run until a real later SIGCONT; queuing a
                // self-signal here would allow cleanup to race ahead of the
                // kernel's process-wide stop.
                match guard.stop_parent() {
                    Some(true) => {}
                    Some(false) => {
                        SUSPEND_ARMED.store(false, Ordering::SeqCst);
                        guard.disarm();
                        let groups = end_suspend(&state);
                        if PENDING_TERMINATION.load(Ordering::SeqCst) == 0 {
                            signal_groups(&groups, libc::SIGCONT);
                        }
                        continue;
                    }
                    None => {
                        SUSPEND_ARMED.store(false, Ordering::SeqCst);
                        guard.disarm();
                        let _ = end_suspend(&state);
                        let _ = PENDING_TERMINATION.compare_exchange(
                            0,
                            libc::SIGTERM,
                            Ordering::SeqCst,
                            Ordering::SeqCst,
                        );
                        continue;
                    }
                }
                SUSPEND_ARMED.store(false, Ordering::SeqCst);
                guard.disarm();
                let groups = end_suspend(&state);
                let terminating = PENDING_TERMINATION.load(Ordering::SeqCst) != 0;
                let _ = CONTINUE_REQUESTED.swap(false, Ordering::SeqCst);
                if !terminating {
                    signal_groups(&groups, libc::SIGCONT);
                }
                continue;
            }

            if CONTINUE_REQUESTED.swap(false, Ordering::SeqCst) {
                if let Some(groups) = groups_when_registered(&state, false) {
                    signal_groups(&groups, libc::SIGCONT);
                } else {
                    CONTINUE_REQUESTED.store(true, Ordering::SeqCst);
                }
            }

            thread::sleep(Duration::from_millis(10));
        }
    }

    fn groups_when_registered(
        state: &Arc<Mutex<State>>,
        terminating: bool,
    ) -> Option<GroupSnapshot> {
        let mut locked = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if locked.spawning != 0 {
            return None;
        }
        if terminating {
            locked.terminating = true;
        }
        Some(snapshot_groups(state, &mut locked))
    }

    fn begin_suspend(state: &Arc<Mutex<State>>) -> Option<(GroupSnapshot, Guard)> {
        let mut locked = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if locked.spawning != 0 || locked.suspending || locked.terminating {
            return None;
        }
        locked.suspending = true;
        let guard = locked.guard;
        Some((snapshot_groups(state, &mut locked), guard))
    }

    fn end_suspend(state: &Arc<Mutex<State>>) -> GroupSnapshot {
        let mut locked = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        locked.suspending = false;
        snapshot_groups(state, &mut locked)
    }

    fn snapshot_groups(state: &Arc<Mutex<State>>, locked: &mut State) -> GroupSnapshot {
        let mut pgids = Vec::with_capacity(locked.groups.len());
        for group in &mut locked.groups {
            group.signal_leases = group.signal_leases.saturating_add(1);
            pgids.push(group.pgid);
        }
        GroupSnapshot {
            state: Arc::clone(state),
            pgids,
        }
    }

    fn remove_unpinned_group(state: &mut State, pgid: i32) -> bool {
        let Some(index) = state.groups.iter().position(|group| group.pgid == pgid) else {
            return true;
        };
        if state.groups[index].signal_leases != 0 {
            return false;
        }
        state.groups.swap_remove(index);
        true
    }

    impl Reaper {
        /// Register from `Command::pre_exec`, where allocation and Rust locks
        /// are forbidden. Launches are serialized, so the shared one-byte
        /// acknowledgement belongs to this registration frame.
        fn register_raw(self, pgid: libc::pid_t) -> bool {
            self.transact_raw(REAPER_REGISTER, pgid) == Some(REAPER_OK)
        }

        fn cleanup(self, pgid: libc::pid_t) -> bool {
            let cleaned = self.transact_raw(REAPER_CLEANUP, pgid) == Some(REAPER_OK);
            self.close_and_wait();
            cleaned
        }

        fn transact_raw(self, operation: u8, pgid: libc::pid_t) -> Option<u8> {
            let mut frame = [0_u8; 5];
            frame[0] = operation;
            frame[1..].copy_from_slice(&pgid.to_ne_bytes());
            if !write_raw(self.command_fd, &frame) {
                return None;
            }
            read_raw_byte(self.ack_fd)
        }

        fn cancel(self) {
            let mut frame = [0_u8; 5];
            frame[0] = REAPER_CANCEL;
            let cancelled = write_raw(self.command_fd, &frame)
                && read_guard_ack(self.ack_fd, Duration::from_secs(2)) == Some(REAPER_OK);
            if !cancelled {
                // The parent does not know whether pre_exec registered a group
                // before spawn failed. Arm ordinary fail-closed termination;
                // the independently polling reaper will observe reparenting
                // and complete any registered cleanup without trusting EOF.
                let _ = PENDING_TERMINATION.compare_exchange(
                    0,
                    libc::SIGTERM,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
                close_fd(self.command_fd);
                close_fd(self.ack_fd);
                close_fd(self._command_keepalive_fd);
                return;
            }
            self.close_and_wait();
        }

        fn close_and_wait(self) {
            close_fd(self.command_fd);
            close_fd(self.ack_fd);
            close_fd(self._command_keepalive_fd);
            loop {
                let waited = unsafe { libc::waitpid(self.pid, std::ptr::null_mut(), 0) };
                if waited == self.pid || (waited < 0 && !last_errno_is_interrupted()) {
                    return;
                }
            }
        }
    }

    fn spawn_reaper() -> Result<Reaper, String> {
        use std::os::unix::ffi::OsStrExt;

        verify_group_scanner()?;
        let parent = unsafe { libc::getpid() };
        let cleanup_paths = crate::rundir::active_cleanup_lease_paths()
            .into_iter()
            .map(|path| {
                std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
                    format!(
                        "run cleanup-lease path contains a null byte: {}",
                        path.display()
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        #[cfg(test)]
        let cleanup_delay_ms = std::env::var("TACTUS_TEST_CLEANUP_DELAY_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        #[cfg(not(test))]
        let cleanup_delay_ms = 0;
        let open_max = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
        if open_max <= 0 {
            return Err("reading the Unix open-file descriptor ceiling".to_owned());
        }
        let open_max = libc::c_int::try_from(open_max)
            .map_err(|_| "Unix open-file descriptor ceiling exceeds c_int".to_owned())?;
        // Rendered BEFORE the fork, like `cleanup_paths` above and for the same
        // reason: the reaper may not allocate. `None` is the ordinary state of
        // every run today — nothing selects a container Runner until PR12 — and
        // costs the reaper nothing at all.
        let containers = container_scope_for_a_new_reaper();
        let command = create_cloexec_pipe()
            .map_err(|error| format!("creating Unix cleanup-reaper command pipe: {error}"))?;
        let ack = match create_cloexec_pipe() {
            Ok(pipe) => pipe,
            Err(error) => {
                close_fd(command[0]);
                close_fd(command[1]);
                return Err(format!(
                    "creating Unix cleanup-reaper acknowledgement pipe: {error}"
                ));
            }
        };
        // SAFETY: the child immediately enters a fixed-storage syscall-only
        // loop. It never returns to the multithreaded Rust runtime.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            for fd in [command[0], command[1], ack[0], ack[1]] {
                close_fd(fd);
            }
            return Err(format!(
                "starting Unix cleanup reaper: {}",
                std::io::Error::last_os_error()
            ));
        }
        if pid == 0 {
            if !install_reaper_dispositions() {
                unsafe { libc::_exit(1) };
            }
            close_fd(command[1]);
            close_fd(ack[0]);
            // A separate process group is the crucial boundary: an
            // uncatchable kill of Tactus's foreground job must not also kill
            // the process that owns its final agent cleanup.
            if unsafe { libc::setpgid(0, 0) } != 0 {
                unsafe { libc::_exit(1) };
            }
            close_inherited_fds(&[command[0], ack[1]], open_max);
            if !lock_cleanup_paths(&cleanup_paths) {
                unsafe { libc::_exit(1) };
            }
            reaper_loop(
                parent,
                command[0],
                ack[1],
                open_max,
                cleanup_delay_ms,
                containers.as_ref(),
            );
        }

        // Close the parent's race with the child-side setpgid. Either call may
        // win; both establish the same private group before any agent exists.
        if unsafe { libc::setpgid(pid, pid) } != 0 {
            let error = last_errno();
            if error != libc::EACCES && error != libc::EPERM {
                for fd in [command[0], command[1], ack[0], ack[1]] {
                    close_fd(fd);
                }
                unsafe {
                    let _ = libc::kill(pid, libc::SIGKILL);
                    let _ = libc::waitpid(pid, std::ptr::null_mut(), 0);
                }
                return Err(format!(
                    "isolating Unix cleanup reaper: {}",
                    std::io::Error::from_raw_os_error(error)
                ));
            }
        }
        close_fd(ack[1]);
        let reaper = Reaper {
            command_fd: command[1],
            ack_fd: ack[0],
            _command_keepalive_fd: command[0],
            pid,
        };
        if read_guard_ack(ack[0], Duration::from_secs(2)) != Some(REAPER_READY) {
            reaper.cancel();
            return Err("Unix cleanup reaper did not initialize".to_owned());
        }
        #[cfg(test)]
        if let Some(path) = std::env::var_os("TACTUS_TEST_REAPER_PID_PATH") {
            if let Err(error) = std::fs::write(&path, pid.to_string()) {
                reaper.cancel();
                return Err(format!(
                    "recording test cleanup-reaper pid at {}: {error}",
                    std::path::Path::new(&path).display()
                ));
            }
        }
        Ok(reaper)
    }

    fn install_reaper_dispositions() -> bool {
        unsafe {
            // This child never executes embedding-host code. Remove every
            // inherited callback before clearing its signal mask; SIGCHLD is
            // restored to default immediately below because the reaper owns
            // the stopped anchor's wait lifecycle.
            if !scrub_private_helper_dispositions() {
                return false;
            }
            // A library host may own SIGCHLD and reap children from its
            // handler. The private reaper must not inherit that callback (or
            // SA_NOCLDWAIT): either can consume the stopped anchor before the
            // reaper's blocking waitpid observes it.
            let mut child_action: libc::sigaction = std::mem::zeroed();
            child_action.sa_sigaction = libc::SIG_DFL;
            child_action.sa_flags = 0;
            if libc::sigemptyset(&mut child_action.sa_mask) != 0
                || libc::sigaction(libc::SIGCHLD, &child_action, std::ptr::null_mut()) != 0
            {
                return false;
            }
            for signal in [
                libc::SIGINT,
                libc::SIGTERM,
                libc::SIGHUP,
                libc::SIGQUIT,
                libc::SIGTSTP,
                libc::SIGCONT,
                libc::SIGPIPE,
            ] {
                if libc::signal(signal, libc::SIG_IGN) == libc::SIG_ERR {
                    return false;
                }
            }
            let mut empty: libc::sigset_t = std::mem::zeroed();
            if libc::sigemptyset(&mut empty) != 0
                || libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut()) != 0
            {
                return false;
            }
        }
        true
    }

    fn lock_cleanup_paths(paths: &[std::ffi::CString]) -> bool {
        for path in paths {
            let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
            if fd < 0 || unsafe { libc::flock(fd, libc::LOCK_SH | libc::LOCK_NB) } != 0 {
                if fd >= 0 {
                    close_fd(fd);
                }
                return false;
            }
            // Deliberately leave this independently opened descriptor live.
            // Process exit releases its shared lease after cleanup completes.
        }
        true
    }

    fn reaper_loop(
        parent: libc::pid_t,
        command_fd: libc::c_int,
        ack_fd: libc::c_int,
        open_max: libc::c_int,
        cleanup_delay_ms: u64,
        containers: Option<&ReaperContainers>,
    ) -> ! {
        let mut pgid = 0_i32;
        let mut anchor = 0_i32;
        let mut mirrored_parent_stop = false;
        let mut parent_running_polls = 0_u8;
        if !write_raw(ack_fd, &[REAPER_READY]) {
            unsafe { libc::_exit(1) };
        }
        loop {
            let mut command = libc::pollfd {
                fd: command_fd,
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            };
            // Poll even before registration. An exec-racing descendant may
            // retain a FIFO writer until it exits, so EOF is not a trustworthy
            // parent-liveness signal on Darwin. Reparenting is authoritative
            // and lets this fork-only helper settle independently.
            let polled = unsafe { libc::poll(&mut command, 1, 10) };
            if polled < 0 {
                if last_errno_is_interrupted() {
                    continue;
                }
                settle_after_coordinator_death(pgid, anchor, cleanup_delay_ms, containers);
                unsafe { libc::_exit(0) };
            }
            if unsafe { libc::getppid() } != parent {
                settle_after_coordinator_death(pgid, anchor, cleanup_delay_ms, containers);
                unsafe { libc::_exit(0) };
            }
            if polled > 0 && command.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                settle_after_coordinator_death(pgid, anchor, cleanup_delay_ms, containers);
                unsafe { libc::_exit(0) };
            }
            if polled > 0 && command.revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                let mut frame = [0_u8; 5];
                if !read_raw_exact(command_fd, &mut frame) {
                    settle_after_coordinator_death(pgid, anchor, cleanup_delay_ms, containers);
                    unsafe { libc::_exit(0) };
                }
                let requested = i32::from_ne_bytes([frame[1], frame[2], frame[3], frame[4]]);
                let accepted = match frame[0] {
                    REAPER_REGISTER if pgid == 0 && requested > 0 => {
                        let created = spawn_group_anchor(requested, open_max);
                        if created <= 0 {
                            false
                        } else {
                            pgid = requested;
                            anchor = created;
                            true
                        }
                    }
                    REAPER_CLEANUP if requested == pgid && pgid > 0 => {
                        cleanup_reaper_group(pgid, anchor, cleanup_delay_ms);
                        let _ = write_raw(ack_fd, &[REAPER_OK]);
                        unsafe { libc::_exit(0) };
                    }
                    REAPER_CANCEL if requested == 0 => {
                        if pgid > 0 {
                            cleanup_reaper_group(pgid, anchor, cleanup_delay_ms);
                        }
                        let _ = write_raw(ack_fd, &[REAPER_OK]);
                        unsafe { libc::_exit(0) };
                    }
                    _ => false,
                };
                if !write_raw(ack_fd, &[if accepted { REAPER_OK } else { REAPER_FAIL }]) {
                    settle_after_coordinator_death(pgid, anchor, cleanup_delay_ms, containers);
                    unsafe { libc::_exit(0) };
                }
            }

            if pgid > 0 {
                match process_is_stopped(parent) {
                    Some(true) if !mirrored_parent_stop => {
                        mirrored_parent_stop = unsafe { libc::kill(-pgid, libc::SIGSTOP) } == 0;
                        parent_running_polls = 0;
                    }
                    Some(true) => parent_running_polls = 0,
                    state @ Some(false) if mirrored_parent_stop => {
                        if parent_has_stably_resumed(state, &mut parent_running_polls) {
                            let _ = unsafe { libc::kill(-pgid, libc::SIGCONT) };
                            mirrored_parent_stop = false;
                            parent_running_polls = 0;
                        }
                    }
                    Some(false) => parent_running_polls = 0,
                    None => parent_running_polls = 0,
                }
            }
        }
    }

    fn parent_has_stably_resumed(stopped: Option<bool>, running_polls: &mut u8) -> bool {
        if stopped != Some(false) {
            *running_polls = 0;
            return false;
        }
        *running_polls = running_polls.saturating_add(1);
        *running_polls >= REAPER_RESUME_STABLE_POLLS
    }

    fn spawn_group_anchor(pgid: i32, open_max: libc::c_int) -> libc::pid_t {
        let anchor = unsafe { libc::fork() };
        if anchor < 0 {
            return -1;
        }
        if anchor == 0 {
            if unsafe { libc::setpgid(0, pgid) } != 0 {
                unsafe { libc::_exit(1) };
            }
            close_inherited_fds(&[], open_max);
            unsafe {
                libc::raise(libc::SIGSTOP);
                loop {
                    libc::pause();
                }
            }
        }
        let mut status = 0;
        loop {
            let waited = unsafe { libc::waitpid(anchor, &mut status, libc::WUNTRACED) };
            if waited == anchor {
                if libc::WIFSTOPPED(status) {
                    return anchor;
                }
                return -1;
            }
            if waited < 0 && !last_errno_is_interrupted() {
                return -1;
            }
        }
    }

    fn cleanup_reaper_group(pgid: i32, anchor: libc::pid_t, cleanup_delay_ms: u64) {
        // Signal the kernel-owned group identity first. Even if the platform's
        // membership scanner subsequently becomes unavailable, no owned
        // process can keep running or spending while cleanup waits fail-closed.
        unsafe {
            let _ = libc::kill(-pgid, libc::SIGKILL);
        }
        // Test subprocesses can widen the otherwise tiny post-crash window so
        // the reaper-owned cleanup lease is asserted deterministically.
        // Release builds always pass zero and pay no delay.
        let mut delay_left = cleanup_delay_ms;
        while delay_left > 0 {
            raw_sleep_10ms();
            delay_left = delay_left.saturating_sub(10);
        }
        // The stopped anchor pins the PGID until it becomes our unreaped
        // zombie. Only release the reaper-owned run-cleanup lease once every
        // member of that exact group is either gone or a non-running zombie.
        while group_has_non_zombie_members(pgid) != Some(false) {
            raw_sleep_10ms();
            unsafe {
                let _ = libc::kill(-pgid, libc::SIGKILL);
            }
        }
        if anchor > 0 {
            loop {
                let waited = unsafe { libc::waitpid(anchor, std::ptr::null_mut(), 0) };
                if waited == anchor || (waited < 0 && !last_errno_is_interrupted()) {
                    break;
                }
            }
        }
    }

    fn write_raw(fd: libc::c_int, bytes: &[u8]) -> bool {
        let mut offset = 0;
        while offset < bytes.len() {
            let written =
                unsafe { libc::write(fd, bytes.as_ptr().add(offset).cast(), bytes.len() - offset) };
            if written > 0 {
                offset += written as usize;
            } else if written < 0 && last_errno_is_interrupted() {
                continue;
            } else {
                return false;
            }
        }
        true
    }

    fn read_raw_exact(fd: libc::c_int, bytes: &mut [u8]) -> bool {
        let mut offset = 0;
        while offset < bytes.len() {
            let read = unsafe {
                libc::read(
                    fd,
                    bytes.as_mut_ptr().add(offset).cast(),
                    bytes.len() - offset,
                )
            };
            if read > 0 {
                offset += read as usize;
            } else if read < 0 && last_errno_is_interrupted() {
                continue;
            } else {
                return false;
            }
        }
        true
    }

    fn read_raw_byte(fd: libc::c_int) -> Option<u8> {
        let mut byte = 0_u8;
        read_raw_exact(fd, std::slice::from_mut(&mut byte)).then_some(byte)
    }

    impl Guard {
        fn abort_setup(self) {
            let _ = GUARD_COMMAND_FD.compare_exchange(
                self.command_fd,
                -1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
            PROBE_PID.store(-1, Ordering::SeqCst);
            for fd in [self.command_fd, self.ack_fd, self._command_keepalive_fd] {
                close_fd(fd);
            }
            // SAFETY: `pid` is the unreaped child returned by `fork`. Killing
            // the guard closes its probe pipe, so the descriptor-scrubbed
            // grandchild exits as well.
            unsafe {
                let _ = libc::kill(self.pid, libc::SIGKILL);
                loop {
                    if libc::waitpid(self.pid, std::ptr::null_mut(), 0) >= 0
                        || !last_errno_is_interrupted()
                    {
                        break;
                    }
                }
            }
        }

        fn arm(self) -> bool {
            write_byte(self.command_fd, GUARD_ARM) && self.read_ack() == Some(GUARD_ARM)
        }

        /// Returns `Some(true)` only after the guard sent SIGSTOP and this
        /// process subsequently resumed. `Some(false)` means a concurrent
        /// continue/termination cancelled the stop before it was issued.
        fn stop_parent(self) -> Option<bool> {
            if !write_byte(self.command_fd, GUARD_STOP) {
                return None;
            }
            match read_guard_ack_blocking(self.ack_fd)? {
                GUARD_STOPPED => Some(true),
                GUARD_CANCELLED => Some(false),
                _ => None,
            }
        }

        fn disarm(self) {
            let _ = write_byte(self.command_fd, GUARD_DISARM);
        }

        fn read_ack(self) -> Option<u8> {
            read_guard_ack(self.ack_fd, Duration::from_secs(2))
        }
    }

    fn read_guard_ack(fd: libc::c_int, timeout: Duration) -> Option<u8> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return None;
            }
            let timeout_ms = i32::try_from(remaining.as_millis().min(i32::MAX as u128))
                .unwrap_or(i32::MAX)
                .max(1);
            let mut poll_fd = libc::pollfd {
                fd,
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            };
            // SAFETY: `poll_fd` is valid for one entry and the bounded timeout
            // prevents a failed guard wedging the signal monitor.
            let polled = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };
            if polled == 0 {
                return None;
            }
            if polled < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return None;
            }
            let mut ack = 0_u8;
            // SAFETY: `fd` is the dedicated guard-to-parent pipe and `ack` is
            // valid writable storage for exactly one byte.
            let read = unsafe { libc::read(fd, (&mut ack as *mut u8).cast(), 1) };
            if read == 1 {
                return Some(ack);
            }
            if read == 0 {
                return None;
            }
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                return None;
            }
        }
    }

    fn read_guard_ack_blocking(fd: libc::c_int) -> Option<u8> {
        loop {
            let mut ack = 0_u8;
            // SAFETY: `fd` is the dedicated guard-to-parent pipe and `ack` is
            // valid writable storage for exactly one byte. This intentionally
            // blocks for the whole user-controlled suspension interval.
            let read = unsafe { libc::read(fd, (&mut ack as *mut u8).cast(), 1) };
            if read == 1 {
                return Some(ack);
            }
            if read == 0 {
                return None;
            }
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                return None;
            }
        }
    }

    fn write_byte(fd: libc::c_int, byte: u8) -> bool {
        loop {
            // SAFETY: `fd` is a dedicated pipe and `byte` remains valid for
            // the duration of the one-byte write.
            let written = unsafe { libc::write(fd, (&byte as *const u8).cast(), 1) };
            if written == 1 {
                return true;
            }
            if written < 0 && last_errno_is_interrupted() {
                continue;
            }
            return false;
        }
    }

    fn spawn_guard(policy: SignalPolicy) -> Result<Guard, String> {
        // Resolve the descriptor ceiling before fork: sysconf may take libc
        // locks, whereas the multithreaded child may call only async-safe
        // primitives until it enters the guard loop.
        let open_max = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
        if open_max <= 0 {
            return Err("reading the Unix open-file descriptor ceiling".to_owned());
        }
        let open_max = libc::c_int::try_from(open_max)
            .map_err(|_| "Unix open-file descriptor ceiling exceeds c_int".to_owned())?;
        let command = create_cloexec_pipe()
            .map_err(|error| format!("creating Unix job-control command pipe: {error}"))?;
        let ack = match create_cloexec_pipe() {
            Ok(pipe) => pipe,
            Err(error) => {
                for fd in command {
                    close_fd(fd);
                }
                return Err(format!(
                    "creating Unix job-control acknowledgement pipe: {error}"
                ));
            }
        };
        let wake = match create_cloexec_pipe() {
            Ok(pipe) => pipe,
            Err(error) => {
                for fd in [command[0], command[1], ack[0], ack[1]] {
                    close_fd(fd);
                }
                return Err(format!("creating Unix job-control wake pipe: {error}"));
            }
        };
        let probe = match create_cloexec_pipe() {
            Ok(pipe) => pipe,
            Err(error) => {
                for fd in [command[0], command[1], ack[0], ack[1], wake[0], wake[1]] {
                    close_fd(fd);
                }
                return Err(format!("creating Unix job-control probe pipe: {error}"));
            }
        };
        if !set_nonblocking(wake[0]) || !set_nonblocking(wake[1]) {
            for fd in [
                command[0], command[1], ack[0], ack[1], wake[0], wake[1], probe[0], probe[1],
            ] {
                close_fd(fd);
            }
            return Err(format!(
                "creating Unix job-control wake/probe pipe: {}",
                std::io::Error::last_os_error()
            ));
        }
        GUARD_WAKE_FD.store(wake[1], Ordering::SeqCst);

        // SAFETY: the child enters `guard_loop` immediately, which uses only
        // libc syscalls and lock-free atomics after fork. It closes every
        // inherited descriptor except its two pipes before doing any work.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            GUARD_WAKE_FD.store(-1, Ordering::SeqCst);
            for fd in [
                command[0], command[1], ack[0], ack[1], wake[0], wake[1], probe[0], probe[1],
            ] {
                close_fd(fd);
            }
            return Err(format!(
                "starting Unix job-control guard: {}",
                std::io::Error::last_os_error()
            ));
        }
        if pid == 0 {
            // Replace inherited host callbacks and clear the inherited mask as
            // the first child-side action. Descriptor scrubbing can be long on
            // high-limit hosts; no signal in that window may run host code or
            // leave the only wake relay blocked.
            if !install_guard_dispositions(policy) {
                unsafe { libc::_exit(1) };
            }
            let parent = unsafe { libc::getppid() };
            let probe_pid = unsafe { libc::fork() };
            if probe_pid < 0 {
                unsafe { libc::_exit(1) };
            }
            if probe_pid == 0 {
                if !install_probe_dispositions() {
                    unsafe { libc::_exit(1) };
                }
                close_fd(probe[1]);
                close_inherited_fds(&[probe[0]], open_max);
                probe_loop(parent, probe[0]);
            }
            close_fd(command[1]);
            close_fd(ack[0]);
            close_fd(probe[0]);
            close_inherited_fds(&[command[0], ack[1], wake[0], wake[1], probe[1]], open_max);
            guard_loop(parent, command[0], ack[1], wake[0], probe[1], probe_pid);
        }

        GUARD_WAKE_FD.store(-1, Ordering::SeqCst);
        close_fd(ack[1]);
        close_fd(wake[0]);
        close_fd(wake[1]);
        close_fd(probe[0]);
        close_fd(probe[1]);
        if !set_nonblocking(command[1]) {
            for fd in [command[0], command[1], ack[0]] {
                close_fd(fd);
            }
            unsafe {
                let _ = libc::kill(pid, libc::SIGKILL);
                let _ = libc::waitpid(pid, std::ptr::null_mut(), 0);
            }
            return Err("configuring Unix job-control guard descriptors".to_owned());
        }
        let guard = Guard {
            command_fd: command[1],
            ack_fd: ack[0],
            _command_keepalive_fd: command[0],
            pid,
        };
        let mut probe_pid_bytes = [0_u8; 4];
        if guard.read_ack() != Some(GUARD_READY)
            || !read_raw_exact(ack[0], &mut probe_pid_bytes)
            || i32::from_ne_bytes(probe_pid_bytes) <= 0
        {
            for fd in [command[0], command[1], ack[0]] {
                close_fd(fd);
            }
            // SAFETY: `pid` is the child returned by fork and has not been
            // reaped. A failed setup acknowledgement must not leave it alive.
            unsafe {
                let _ = libc::kill(pid, libc::SIGKILL);
                let _ = libc::waitpid(pid, std::ptr::null_mut(), 0);
            }
            return Err("Unix job-control guard did not initialize".to_owned());
        }
        PROBE_PID.store(i32::from_ne_bytes(probe_pid_bytes), Ordering::SeqCst);
        GUARD_COMMAND_FD.store(command[1], Ordering::SeqCst);
        Ok(guard)
    }

    fn guard_loop(
        parent: libc::pid_t,
        command_fd: libc::c_int,
        ack_fd: libc::c_int,
        wake_fd: libc::c_int,
        probe_fd: libc::c_int,
        probe_pid: libc::pid_t,
    ) -> ! {
        let mut ready = [0_u8; 5];
        ready[0] = GUARD_READY;
        ready[1..].copy_from_slice(&probe_pid.to_ne_bytes());
        if !write_raw(ack_fd, &ready) {
            unsafe { libc::_exit(1) };
        }
        let mut armed = false;
        let mut stopping = false;
        let mut wake = false;
        let mut buffer = [0_u8; 64];
        loop {
            let mut poll_fds = [
                libc::pollfd {
                    fd: command_fd,
                    events: libc::POLLIN | libc::POLLHUP,
                    revents: 0,
                },
                libc::pollfd {
                    fd: wake_fd,
                    events: libc::POLLIN | libc::POLLHUP,
                    revents: 0,
                },
            ];
            // Both parent relays and guard-directed foreground signals make a
            // descriptor readable, so there is no atomic-check-to-poll window.
            // While the parent is SIGSTOPped, a signal sent only to its PID
            // cannot run a caught handler. Periodically resume only the parent;
            // its SA_SIGINFO SIGCONT handler recognizes this guard as sender,
            // delivers any pending Tactus-owned termination, or immediately
            // re-stops. Agent groups remain stopped throughout.
            let timeout_ms = if armed && stopping { 250 } else { -1 };
            let polled = unsafe { libc::poll(poll_fds.as_mut_ptr(), 2, timeout_ms) };
            if polled < 0 && !last_errno_is_interrupted() {
                unsafe { libc::_exit(1) };
            }
            if polled == 0 && armed && stopping {
                if unsafe { libc::getppid() } != parent || !write_byte(probe_fd, GUARD_PROBE) {
                    unsafe { libc::_exit(0) };
                }
                continue;
            }
            if polled > 0 && poll_fds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                // SAFETY: `buffer` is valid writable storage and command_fd is
                // the guard's private read end.
                let count =
                    unsafe { libc::read(command_fd, buffer.as_mut_ptr().cast(), buffer.len()) };
                if count <= 0 {
                    unsafe { libc::_exit(0) };
                }
                for byte in &buffer[..count as usize] {
                    match *byte {
                        GUARD_ARM => {
                            // ARM is an epoch boundary. Signals observed before
                            // it are already represented in the parent's
                            // atomics and checked after this acknowledgement;
                            // retaining them would spuriously continue a later
                            // stop. A signal racing after this clear is caught
                            // by its ordered command or wake-pipe record.
                            wake = false;
                            stopping = false;
                            drain_pipe(wake_fd);
                            armed = true;
                            let _ =
                                unsafe { libc::write(ack_fd, (&GUARD_ARM as *const u8).cast(), 1) };
                        }
                        GUARD_STOP => {
                            if !armed || wake {
                                let _ = write_byte(ack_fd, GUARD_CANCELLED);
                                armed = false;
                                stopping = false;
                                wake = false;
                                continue;
                            }
                            // PID reuse must never redirect a late stop to an
                            // unrelated process. Reparenting proves the
                            // original Tactus process is gone.
                            if unsafe { libc::getppid() } != parent {
                                unsafe { libc::_exit(0) };
                            }
                            // The parent is blocked reading this ack pipe. The
                            // stop is queued before the acknowledgement write,
                            // so it cannot return to userspace until a later
                            // SIGCONT has genuinely resumed it.
                            if unsafe { libc::kill(parent, libc::SIGSTOP) } != 0 {
                                unsafe { libc::_exit(0) };
                            }
                            stopping = true;
                        }
                        GUARD_DISARM => {
                            armed = false;
                            stopping = false;
                            wake = false;
                            drain_pipe(wake_fd);
                        }
                        _ => wake = true,
                    }
                }
            }
            if polled > 0 && poll_fds[1].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                drain_pipe(wake_fd);
                wake = true;
            }
            if armed && stopping && wake {
                // PID reuse must never redirect a late guard wake to an
                // unrelated process. Reparenting proves the original Tactus
                // process is gone even if its numeric pid has been reused.
                if unsafe { libc::getppid() } != parent {
                    unsafe { libc::_exit(0) };
                }
                // SAFETY: a positive pid targets only the Tactus parent. A
                // generated SIGCONT resumes it even while blocked or caught.
                if unsafe { libc::kill(parent, libc::SIGCONT) } != 0 {
                    unsafe { libc::_exit(0) };
                }
                if !write_byte(ack_fd, GUARD_STOPPED) {
                    unsafe { libc::_exit(0) };
                }
                armed = false;
                stopping = false;
                wake = false;
            }
        }
    }

    /// Remove every embedding-host callback from a fork-only helper.
    ///
    /// Signal numbers are sparse and platform-specific. `sigaction` reports
    /// EINVAL for holes, uncatchable signals, and values above the platform's
    /// range, so a fixed upper bound avoids non-portable NSIG APIs while still
    /// covering Linux real-time and BSD/macOS signals. Asynchronous signals
    /// are ignored so a broadcast cannot disable cleanup; synchronous faults
    /// retain their ordinary fatal behavior.
    fn scrub_private_helper_dispositions() -> bool {
        for signal in 1..=128 {
            if signal == libc::SIGKILL || signal == libc::SIGSTOP {
                continue;
            }
            let synchronous = matches!(
                signal,
                libc::SIGILL
                    | libc::SIGABRT
                    | libc::SIGFPE
                    | libc::SIGSEGV
                    | libc::SIGBUS
                    | libc::SIGTRAP
                    | libc::SIGSYS
            );
            let disposition = if synchronous {
                libc::SIG_DFL
            } else {
                libc::SIG_IGN
            };
            if !set_signal_disposition(signal, disposition) {
                return false;
            }
        }
        true
    }

    fn set_signal_disposition(signal: libc::c_int, disposition: libc::sighandler_t) -> bool {
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = disposition;
            action.sa_flags = 0;
            if libc::sigemptyset(&mut action.sa_mask) != 0 {
                return false;
            }
            if libc::sigaction(signal, &action, std::ptr::null_mut()) == 0 {
                true
            } else {
                last_errno() == libc::EINVAL
            }
        }
    }

    fn install_probe_dispositions() -> bool {
        unsafe {
            if !scrub_private_helper_dispositions() {
                return false;
            }
            let mut empty: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut empty) == 0
                && libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut()) == 0
        }
    }

    fn probe_loop(parent: libc::pid_t, command_fd: libc::c_int) -> ! {
        loop {
            let mut command = 0_u8;
            let read = unsafe { libc::read(command_fd, (&mut command as *mut u8).cast(), 1) };
            if read == 1 && command == GUARD_PROBE {
                if unsafe { libc::kill(parent, libc::SIGCONT) } == 0 {
                    continue;
                }
            } else if read < 0 && last_errno_is_interrupted() {
                continue;
            }
            unsafe { libc::_exit(0) };
        }
    }

    fn install_guard_dispositions(policy: SignalPolicy) -> bool {
        // The guard stays in the foreground process group but cannot join the
        // stop: it ignores SIGTSTP and records every transition that must wake
        // a parent already stopped by the guard. SIGSTOP itself targets only
        // the parent pid.
        unsafe {
            // Scrub before deliberately clearing the inherited mask. Only this
            // guard's narrow supervision surface is installed below.
            if !scrub_private_helper_dispositions() {
                return false;
            }
            // A library host may have blocked these signals on the thread
            // that first invoked Tactus. The guard is an isolated relay, not
            // host code: clear its inherited mask so it can always wake a
            // parent that it previously stopped.
            let mut empty: libc::sigset_t = std::mem::zeroed();
            if libc::sigemptyset(&mut empty) != 0
                || libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut()) != 0
            {
                return false;
            }
            if policy.job_control {
                if libc::signal(libc::SIGTSTP, libc::SIG_IGN) == libc::SIG_ERR
                    || libc::signal(
                        libc::SIGCONT,
                        record_guard_signal as *const () as libc::sighandler_t,
                    ) == libc::SIG_ERR
                {
                    return false;
                }
            } else {
                // Job-control callbacks and defaults belong to the embedding
                // parent when Tactus cannot safely proxy the pair. The private
                // guard must neither run fork-copied host code nor stop itself.
                if libc::signal(libc::SIGTSTP, libc::SIG_IGN) == libc::SIG_ERR
                    || libc::signal(libc::SIGCONT, libc::SIG_IGN) == libc::SIG_ERR
                {
                    return false;
                }
            }
            for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
                if policy.wakes_guard(signal) {
                    // Custom callbacks belong to the embedding parent. Never
                    // run a fork-copied callback against the guard's private
                    // memory; translate it into the same self-pipe wake as a
                    // default Tactus-owned termination signal instead.
                    if libc::signal(
                        signal,
                        record_guard_signal as *const () as libc::sighandler_t,
                    ) == libc::SIG_ERR
                    {
                        return false;
                    }
                }
            }
        }
        true
    }

    fn drain_pipe(fd: libc::c_int) {
        let mut buffer = [0_u8; 64];
        loop {
            // SAFETY: `buffer` is writable for its complete length and `fd` is
            // the nonblocking read side of the guard's private wake pipe.
            if unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) } <= 0 {
                return;
            }
        }
    }

    fn close_inherited_fds(keep: &[libc::c_int], open_max: libc::c_int) {
        // The fork must not retain the run lock, event file, pipes, or secrets.
        // Linux close_range keeps this bounded even when RLIMIT_NOFILE is in
        // the millions. Older kernels and other Unix hosts retain the
        // syscall-only per-descriptor fallback.
        #[cfg(target_os = "linux")]
        if close_ranges_except(keep) {
            return;
        }
        for fd in 0..open_max {
            if !keep.contains(&fd) {
                close_fd(fd);
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn close_ranges_except(keep: &[libc::c_int]) -> bool {
        let mut first = 0_u32;
        loop {
            let next_keep = keep
                .iter()
                .copied()
                .filter(|fd| *fd >= 0 && (*fd as u32) >= first)
                .map(|fd| fd as u32)
                .min();
            // `first == kept` is an empty range. Saturating `kept - 1`
            // would turn the fd-zero case into 0..=0 and close the descriptor
            // we were explicitly asked to preserve.
            if next_keep != Some(first) {
                let last = next_keep.map_or(u32::MAX, |fd| fd - 1);
                let result = unsafe { libc::syscall(libc::SYS_close_range, first, last, 0_u32) };
                if result != 0 {
                    return false;
                }
            }
            let Some(kept) = next_keep else {
                return true;
            };
            first = kept + 1;
        }
    }

    fn last_errno_is_interrupted() -> bool {
        last_errno() == libc::EINTR
    }

    fn last_errno() -> libc::c_int {
        #[cfg(target_os = "linux")]
        unsafe {
            *libc::__errno_location()
        }
        #[cfg(target_os = "macos")]
        unsafe {
            *libc::__error()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        }
    }

    fn raw_sleep_10ms() {
        let request = libc::timespec {
            tv_sec: 0,
            tv_nsec: 10_000_000,
        };
        let mut remaining = request;
        loop {
            let result = unsafe { libc::nanosleep(&remaining, &mut remaining) };
            if result == 0 || !last_errno_is_interrupted() {
                return;
            }
        }
    }

    fn verify_group_scanner() -> Result<(), String> {
        let own_group = unsafe { libc::getpgrp() };
        let own_pid = unsafe { libc::getpid() };
        // Process enumeration can race an unrelated process exiting. Retry a
        // bounded realistic interval, but refuse before launching an agent
        // when either cleanup enumeration or parent-state observation is
        // persistently absent (for example a Linux container without a
        // mounted/readable procfs).
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            match (
                group_has_non_zombie_members(own_group),
                process_is_stopped(own_pid),
            ) {
                (Some(true), Some(false)) => return Ok(()),
                (Some(false), _) => {
                    return Err(format!(
                        "Unix process-group scanner did not find the current group {own_group}"
                    ));
                }
                (Some(true), Some(true)) => {
                    return Err(
                        "Unix parent-state scanner reported the running Tactus process as stopped"
                            .to_owned(),
                    );
                }
                _ if std::time::Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(1));
                }
                _ => break,
            }
        }
        Err("Unix process-group scanner is unavailable; refusing to launch an agent whose cleanup could not be verified".to_owned())
    }

    #[cfg(target_os = "linux")]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum LinuxStatSnapshot {
        Present { pgid: i32, state: u8 },
        Vanished,
        Invalid,
    }

    #[cfg(target_os = "linux")]
    fn group_has_non_zombie_members(pgid: i32) -> Option<bool> {
        let directory = unsafe {
            libc::open(
                c"/proc".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if directory < 0 {
            return None;
        }
        let mut entries = [0_u8; 16_384];
        loop {
            let count = unsafe {
                libc::syscall(
                    libc::SYS_getdents64,
                    directory,
                    entries.as_mut_ptr(),
                    entries.len(),
                )
            };
            if count == 0 {
                close_fd(directory);
                return Some(false);
            }
            if count < 0 {
                if last_errno_is_interrupted() {
                    continue;
                }
                close_fd(directory);
                return None;
            }
            let mut offset = 0_usize;
            while offset < count as usize {
                if offset + 19 > count as usize {
                    close_fd(directory);
                    return None;
                }
                let record_len =
                    u16::from_ne_bytes([entries[offset + 16], entries[offset + 17]]) as usize;
                if record_len < 20 || offset + record_len > count as usize {
                    close_fd(directory);
                    return None;
                }
                let name = &entries[offset + 19..offset + record_len];
                let name_len = name
                    .iter()
                    .position(|byte| *byte == 0)
                    .unwrap_or(name.len());
                if let Some(pid) = parse_decimal(&name[..name_len]) {
                    match read_linux_stat_raw(pid) {
                        LinuxStatSnapshot::Present {
                            pgid: candidate,
                            state,
                        } if candidate == pgid && !matches!(state, b'Z' | b'X' | b'x') => {
                            close_fd(directory);
                            return Some(true);
                        }
                        LinuxStatSnapshot::Present { .. } | LinuxStatSnapshot::Vanished => {}
                        // Permission failures and malformed snapshots remain
                        // fail-closed. Only a kernel-confirmed vanished PID is
                        // safe to skip as ordinary process churn.
                        LinuxStatSnapshot::Invalid => {
                            close_fd(directory);
                            return None;
                        }
                    }
                }
                offset += record_len;
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn read_linux_stat_raw(pid: i32) -> LinuxStatSnapshot {
        let mut path = [0_u8; 64];
        let prefix = b"/proc/";
        path[..prefix.len()].copy_from_slice(prefix);
        let mut end = prefix.len();
        let Some(written) = write_decimal(pid, &mut path[end..]) else {
            return LinuxStatSnapshot::Invalid;
        };
        end += written;
        let suffix = b"/stat\0";
        let Some(target) = path.get_mut(end..end + suffix.len()) else {
            return LinuxStatSnapshot::Invalid;
        };
        target.copy_from_slice(suffix);
        let fd = unsafe { libc::open(path.as_ptr().cast(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if fd < 0 {
            return if matches!(last_errno(), libc::ENOENT | libc::ESRCH) {
                LinuxStatSnapshot::Vanished
            } else {
                LinuxStatSnapshot::Invalid
            };
        }
        let mut stat = [0_u8; 2_048];
        let count = loop {
            let read = unsafe { libc::read(fd, stat.as_mut_ptr().cast(), stat.len()) };
            if read < 0 && last_errno_is_interrupted() {
                continue;
            }
            break read;
        };
        let read_errno = (count < 0).then(last_errno);
        close_fd(fd);
        if matches!(read_errno, Some(libc::ENOENT | libc::ESRCH)) {
            return LinuxStatSnapshot::Vanished;
        }
        if count <= 0 {
            return LinuxStatSnapshot::Invalid;
        }
        parse_linux_stat_bytes(&stat[..count as usize])
            .map(|(pgid, state)| LinuxStatSnapshot::Present { pgid, state })
            .unwrap_or(LinuxStatSnapshot::Invalid)
    }

    #[cfg(target_os = "linux")]
    fn process_is_stopped(pid: i32) -> Option<bool> {
        match read_linux_stat_raw(pid) {
            LinuxStatSnapshot::Present { state, .. } => Some(matches!(state, b'T' | b't')),
            LinuxStatSnapshot::Vanished | LinuxStatSnapshot::Invalid => None,
        }
    }

    #[cfg(target_os = "linux")]
    fn parse_linux_stat_bytes(stat: &[u8]) -> Option<(i32, u8)> {
        let close = stat.iter().rposition(|byte| *byte == b')')?;
        let mut fields = stat.get(close + 1..)?;
        fields = trim_ascii_start(fields);
        let state = *fields.first()?;
        fields = next_ascii_field(fields)?.1;
        let (parent, tail) = next_ascii_field(fields)?;
        parse_decimal(parent)?;
        let (group, _) = next_ascii_field(tail)?;
        Some((parse_decimal(group)?, state))
    }

    #[cfg(target_os = "linux")]
    fn next_ascii_field(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
        let bytes = trim_ascii_start(bytes);
        let end = bytes
            .iter()
            .position(u8::is_ascii_whitespace)
            .unwrap_or(bytes.len());
        (end != 0).then_some((&bytes[..end], &bytes[end..]))
    }

    #[cfg(target_os = "linux")]
    fn trim_ascii_start(mut bytes: &[u8]) -> &[u8] {
        while bytes.first().is_some_and(u8::is_ascii_whitespace) {
            bytes = &bytes[1..];
        }
        bytes
    }

    #[cfg(target_os = "linux")]
    fn parse_decimal(bytes: &[u8]) -> Option<i32> {
        if bytes.is_empty() {
            return None;
        }
        let mut value = 0_i32;
        for byte in bytes {
            if !byte.is_ascii_digit() {
                return None;
            }
            value = value.checked_mul(10)?.checked_add(i32::from(byte - b'0'))?;
        }
        Some(value)
    }

    #[cfg(target_os = "linux")]
    fn write_decimal(value: i32, output: &mut [u8]) -> Option<usize> {
        if value <= 0 {
            return None;
        }
        let mut reversed = [0_u8; 10];
        let mut count = 0_usize;
        let mut value = value as u32;
        while value != 0 {
            reversed[count] = b'0' + (value % 10) as u8;
            count += 1;
            value /= 10;
        }
        if output.len() < count {
            return None;
        }
        for index in 0..count {
            output[index] = reversed[count - index - 1];
        }
        Some(count)
    }

    #[cfg(target_os = "macos")]
    fn group_has_non_zombie_members(pgid: i32) -> Option<bool> {
        const PROC_PGRP_ONLY: u32 = 2;
        const MAX_PIDS: usize = 16_384;
        let mut pids = [0_i32; MAX_PIDS];
        let bytes = unsafe {
            libc::proc_listpids(
                PROC_PGRP_ONLY,
                pgid as u32,
                pids.as_mut_ptr().cast(),
                std::mem::size_of_val(&pids) as libc::c_int,
            )
        };
        if bytes < 0 || bytes as usize == std::mem::size_of_val(&pids) {
            return None;
        }
        let count = bytes as usize / std::mem::size_of::<libc::pid_t>();
        for pid in &pids[..count] {
            if *pid <= 0 {
                continue;
            }
            let mut info: libc::proc_bsdshortinfo = unsafe { std::mem::zeroed() };
            let read = unsafe {
                libc::proc_pidinfo(
                    *pid,
                    libc::PROC_PIDT_SHORTBSDINFO,
                    // Apple only searches the zombie table for BSD-info
                    // flavors when this argument is non-zero. Without it an
                    // exited group member is indistinguishable from an
                    // incomplete snapshot and cleanup must wait forever.
                    1,
                    (&mut info as *mut libc::proc_bsdshortinfo).cast(),
                    std::mem::size_of::<libc::proc_bsdshortinfo>() as libc::c_int,
                )
            };
            if read != std::mem::size_of::<libc::proc_bsdshortinfo>() as libc::c_int {
                // A disappearing target-group pid is resolved by the next
                // complete snapshot. Never turn an incomplete observation
                // into permission to release the cleanup lease.
                return None;
            }
            if info.pbsi_pgid == pgid as u32 && info.pbsi_status != libc::SZOMB {
                return Some(true);
            }
        }
        Some(false)
    }

    #[cfg(target_os = "macos")]
    fn process_is_stopped(pid: i32) -> Option<bool> {
        let mut info: libc::proc_bsdshortinfo = unsafe { std::mem::zeroed() };
        let read = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDT_SHORTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdshortinfo).cast(),
                std::mem::size_of::<libc::proc_bsdshortinfo>() as libc::c_int,
            )
        };
        (read == std::mem::size_of::<libc::proc_bsdshortinfo>() as libc::c_int)
            .then_some(info.pbsi_status == libc::SSTOP)
    }

    #[cfg(target_os = "linux")]
    fn create_cloexec_pipe() -> Result<[libc::c_int; 2], std::io::Error> {
        let mut pipe = [-1; 2];
        // SAFETY: `pipe` exposes storage for exactly two descriptors. `pipe2`
        // applies CLOEXEC in the same kernel operation that publishes them, so
        // a concurrent spawn can never inherit an intermediate descriptor.
        if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } == 0 {
            Ok(pipe)
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    #[cfg(target_os = "macos")]
    fn create_cloexec_pipe() -> Result<[libc::c_int; 2], std::io::Error> {
        use std::os::unix::ffi::OsStrExt;

        // Darwin has no pipe2. Build the anonymous-equivalent channel from a
        // FIFO inside an atomic, private mkdtemp directory: each endpoint is
        // opened with O_CLOEXEC in the syscall that creates its descriptor,
        // then the name and directory are removed before this function returns.
        let template =
            std::env::temp_dir().join(format!(".tactus-pipe-{}-XXXXXX", unsafe { libc::getpid() }));
        let mut template = std::ffi::CString::new(template.as_os_str().as_bytes())
            .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?
            .into_bytes_with_nul();
        if unsafe { libc::mkdtemp(template.as_mut_ptr().cast()) }.is_null() {
            return Err(std::io::Error::last_os_error());
        }

        let directory_len = template.len().saturating_sub(1);
        let mut fifo = Vec::with_capacity(directory_len + b"/channel\0".len());
        fifo.extend_from_slice(&template[..directory_len]);
        fifo.extend_from_slice(b"/channel\0");
        let cleanup = || unsafe {
            let _ = libc::unlink(fifo.as_ptr().cast());
            let _ = libc::rmdir(template.as_ptr().cast());
        };
        if unsafe { libc::mkfifo(fifo.as_ptr().cast(), 0o600) } != 0 {
            let error = std::io::Error::last_os_error();
            cleanup();
            return Err(error);
        }

        let read_fd = unsafe {
            libc::open(
                fifo.as_ptr().cast(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if read_fd < 0 {
            let error = std::io::Error::last_os_error();
            cleanup();
            return Err(error);
        }
        let write_fd = unsafe {
            libc::open(
                fifo.as_ptr().cast(),
                libc::O_WRONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if write_fd < 0 {
            let error = std::io::Error::last_os_error();
            close_fd(read_fd);
            cleanup();
            return Err(error);
        }
        let unlinked = unsafe { libc::unlink(fifo.as_ptr().cast()) } == 0;
        let removed = unsafe { libc::rmdir(template.as_ptr().cast()) } == 0;
        if !unlinked || !removed || !clear_nonblocking(read_fd) || !clear_nonblocking(write_fd) {
            let error = std::io::Error::last_os_error();
            close_fd(read_fd);
            close_fd(write_fd);
            return Err(error);
        }
        Ok([read_fd, write_fd])
    }

    #[cfg(target_os = "macos")]
    fn clear_nonblocking(fd: libc::c_int) -> bool {
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            flags >= 0 && libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) == 0
        }
    }

    fn set_nonblocking(fd: libc::c_int) -> bool {
        // Signal handlers may write this descriptor. Nonblocking mode makes a
        // dead or unresponsive guard fail closed instead of wedging Tactus in
        // async-signal context.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags >= 0 {
                return libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) == 0;
            }
        }
        false
    }

    fn close_fd(fd: libc::c_int) {
        if fd >= 0 {
            // SAFETY: callers transfer ownership of each raw descriptor here.
            let _ = unsafe { libc::close(fd) };
        }
    }

    fn signal_groups(groups: &[i32], signal: libc::c_int) {
        for pgid in groups {
            // SAFETY: every registered child was created with
            // `process_group(0)`, so its pid is its private group id. A
            // negative id targets that group and never Tactus's group.
            let _ = unsafe { libc::kill(-*pgid, signal) };
        }
    }

    fn stop_groups(groups: &[i32]) -> bool {
        signal_groups(groups, libc::SIGSTOP);
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            if groups_are_quiescent(groups) {
                return true;
            }
            if std::time::Instant::now() >= deadline
                || PENDING_TERMINATION.load(Ordering::SeqCst) != 0
                || CONTINUE_REQUESTED.load(Ordering::SeqCst)
            {
                return false;
            }
            thread::sleep(Duration::from_millis(1));
        }
    }

    #[cfg(target_os = "linux")]
    fn groups_are_quiescent(groups: &[i32]) -> bool {
        if groups.is_empty() {
            return true;
        }
        // `/proc/<pid>/stat` is a kernel interface and remains available on
        // distributions such as NixOS that intentionally have no `/bin/ps`.
        // It observes every descendant in the process group, not only the
        // direct child that Tactus can wait on.
        let entries = match std::fs::read_dir("/proc") {
            Ok(entries) => entries,
            Err(_) => return false,
        };
        let mut observed = vec![false; groups.len()];
        for entry in entries {
            let Ok(entry) = entry else {
                return false;
            };
            if entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
                .is_none()
            {
                continue;
            }
            let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
                // Processes can disappear between directory enumeration and
                // the read. A still-live target group is caught by either
                // another member or the kill(0) completeness check below.
                continue;
            };
            let Some((pgid, state)) = parse_linux_process_stat(&stat) else {
                return false;
            };
            let Some(index) = groups.iter().position(|candidate| *candidate == pgid) else {
                continue;
            };
            observed[index] = true;
            if !matches!(state, b'T' | b't' | b'Z' | b'X' | b'x') {
                return false;
            }
        }
        quiescent_snapshot_is_complete(groups, &observed)
    }

    #[cfg(target_os = "linux")]
    fn parse_linux_process_stat(stat: &str) -> Option<(i32, u8)> {
        // The parenthesized command may itself contain spaces and `)` bytes;
        // the final close parenthesis is the only reliable field boundary.
        let tail = stat.get(stat.rfind(')')? + 1..)?.trim_start();
        let mut fields = tail.split_whitespace();
        let state = *fields.next()?.as_bytes().first()?;
        let _parent_pid = fields.next()?.parse::<i32>().ok()?;
        let process_group = fields.next()?.parse::<i32>().ok()?;
        Some((process_group, state))
    }

    #[cfg(not(target_os = "linux"))]
    fn groups_are_quiescent(groups: &[i32]) -> bool {
        if groups.is_empty() {
            return true;
        }
        // `/bin/ps` is a fixed base-system interface on macOS; no
        // repository-controlled PATH entry can substitute for it.
        let output = match std::process::Command::new("/bin/ps")
            .args(["-axo", "pgid=,stat="])
            .env("LC_ALL", "C")
            .output()
        {
            Ok(output) if output.status.success() => output,
            _ => return false,
        };
        let listing = String::from_utf8_lossy(&output.stdout);
        let mut observed = vec![false; groups.len()];
        for line in listing.lines() {
            let mut fields = line.split_whitespace();
            let Some(pgid) = fields.next().and_then(|field| field.parse::<i32>().ok()) else {
                continue;
            };
            let Some(index) = groups.iter().position(|candidate| *candidate == pgid) else {
                continue;
            };
            observed[index] = true;
            let Some(state) = fields.next().and_then(|field| field.as_bytes().first()) else {
                return false;
            };
            if !matches!(*state, b'T' | b'Z' | b'X') {
                return false;
            }
        }
        quiescent_snapshot_is_complete(groups, &observed)
    }

    fn quiescent_snapshot_is_complete(groups: &[i32], observed: &[bool]) -> bool {
        for (index, pgid) in groups.iter().enumerate() {
            if observed[index] {
                continue;
            }
            // A group that disappeared between SIGSTOP and the snapshot is
            // already quiescent. Any other result means `ps` failed to account
            // for a still-live member, so do not stop the parent yet.
            if unsafe { libc::kill(-*pgid, 0) } == 0
                || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
            {
                return false;
            }
        }
        true
    }

    // -----------------------------------------------------------------------
    // The container half of the orphan window — ST-16 (d)
    // -----------------------------------------------------------------------

    /// The `docker` argument vectors, rendered before any fork.
    ///
    /// A reaper is a `fork`-only child of a multithreaded process: after the
    /// fork it may call only async-signal-safe functions, so it can neither
    /// format a filter nor allocate an argv. Every byte it will ever need is
    /// therefore built here, on the parent side, exactly as `spawn_reaper`'s
    /// `cleanup_paths` are — and a `CString`'s buffer does not move when the
    /// struct that owns it does, so the pointer array stays valid.
    struct ReaperContainers {
        program: std::ffi::CString,
        /// Kept alive for the pointers in `ps_argv`.
        _ps: Vec<std::ffi::CString>,
        /// NULL-terminated `argv` for `docker ps …`.
        ps_argv: Vec<*const libc::c_char>,
    }

    /// The scope every reaper started from now on inherits, or `None`.
    ///
    /// A reaper already running keeps the scope it was forked with; there is no
    /// channel for handing one a new one, and inventing a wire frame for it
    /// would put a variable-length message into a protocol whose frames are five
    /// bytes.
    static CONTAINER_SCOPE: OnceLock<
        Mutex<Option<crate::runner::container::census::ReaperContainerScope>>,
    > = OnceLock::new();

    /// How many list-and-kill rounds one reaper performs.
    ///
    /// The `docker ps` output is read into a fixed buffer, because a reaper
    /// cannot grow one. A machine with more labeled containers than the buffer
    /// holds is not silently truncated: each round kills and removes what it
    /// read, so the next round's listing is shorter, and the loop stops when a
    /// round finds nothing. Bounded so a runtime that keeps reporting the same
    /// container cannot hold R28 for ever.
    const REAPER_CONTAINER_ROUNDS: usize = 8;

    /// The fixed listing buffer. A `--no-trunc` id is 64 bytes plus a newline,
    /// so this is 126 containers per round.
    const REAPER_PS_BUFFER: usize = 8192;

    /// The ceiling on one `docker` invocation, in 10 ms ticks.
    ///
    /// `determinism` forbids sleeps in tests and this is not one: it is the
    /// fail-safe that keeps a wedged daemon from holding R28 — the shared
    /// cleanup hold the next coordinator waits on — for ever. A reaper that
    /// waited without a bound would convert "docker is hung" into "no run on
    /// this machine can ever start again".
    const REAPER_DOCKER_TICKS: usize = 3_000;

    /// Arm or disarm the container scope. See
    /// [`super::set_container_reclaim_scope`].
    pub(super) fn set_container_reclaim_scope(
        scope: Option<&crate::runner::container::census::ReaperContainerScope>,
    ) -> Result<(), TactusError> {
        // Rendered here so a scope that cannot be turned into argv is refused
        // by the caller that set it, rather than silently doing nothing inside
        // a reaper that has no error channel.
        if let Some(scope) = scope {
            render_container_argv(scope)?;
        }
        let mut held = CONTAINER_SCOPE
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *held = scope.cloned();
        Ok(())
    }

    /// The argument vectors for `scope`, or why they cannot be built.
    fn render_container_argv(
        scope: &crate::runner::container::census::ReaperContainerScope,
    ) -> Result<ReaperContainers, TactusError> {
        let nul = |value: &str| TactusError::Refused {
            message: format!(
                "the Unix reaper's container scope renders `{value}`, which carries an interior \
                 NUL and cannot be an argument to `{}`",
                scope.program().display()
            ),
        };
        let program = std::ffi::CString::new(scope.program().as_os_str().as_encoded_bytes())
            .map_err(|_| nul(&scope.program().to_string_lossy()))?;
        let mut ps = Vec::new();
        for argument in scope.list_argv() {
            ps.push(std::ffi::CString::new(argument.clone()).map_err(|_| nul(&argument))?);
        }
        let mut ps_argv: Vec<*const libc::c_char> =
            ps.iter().map(|argument| argument.as_ptr()).collect();
        ps_argv.push(std::ptr::null());
        Ok(ReaperContainers {
            program,
            _ps: ps,
            ps_argv,
        })
    }

    /// What a reaper about to be forked should carry.
    fn container_scope_for_a_new_reaper() -> Option<ReaperContainers> {
        let scope = CONTAINER_SCOPE
            .get()?
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()?;
        render_container_argv(&scope).ok()
    }

    /// Kill and remove every labeled container of the dead coordinator.
    ///
    /// `T-CONTAINER.resume_action`: "on Unix the cleanup reaper performs
    /// **kill/rm** earlier when the coordinator dies". Only kill and rm: the
    /// Git view and the intent record are removed by the next write command's
    /// census, which is why every step of `runner::container::reclaim` is
    /// idempotent and tolerant of already-gone.
    ///
    /// Every call here is async-signal-safe: `fork`, `execv`, `pipe`, `dup2`,
    /// `open`, `close`, `poll`, `read`, `waitpid`, `kill`, `_exit`.
    fn reclaim_labeled_containers(containers: &ReaperContainers) {
        for _ in 0..REAPER_CONTAINER_ROUNDS {
            let mut buffer = [0_u8; REAPER_PS_BUFFER];
            let filled = list_labeled_containers(containers, &mut buffer);
            if filled == 0 {
                return;
            }
            let mut settled = 0_usize;
            let mut start = 0_usize;
            for index in 0..filled {
                if buffer[index] != b'\n' {
                    continue;
                }
                // NUL-terminate the id where it lies. Nothing is allocated and
                // nothing is copied; the buffer is this frame's own.
                buffer[index] = 0;
                if index > start {
                    let id = buffer[start..].as_ptr().cast::<libc::c_char>();
                    let kill: [*const libc::c_char; 4] = [
                        containers.program.as_ptr(),
                        c"kill".as_ptr(),
                        id,
                        std::ptr::null(),
                    ];
                    spawn_docker(containers.program.as_ptr(), kill.as_ptr());
                    let remove: [*const libc::c_char; 5] = [
                        containers.program.as_ptr(),
                        c"rm".as_ptr(),
                        c"--force".as_ptr(),
                        id,
                        std::ptr::null(),
                    ];
                    spawn_docker(containers.program.as_ptr(), remove.as_ptr());
                    settled = settled.saturating_add(1);
                }
                start = index + 1;
            }
            if settled == 0 {
                return;
            }
        }
    }

    /// Run `docker ps …` and read its ids into `buffer`, returning how many
    /// bytes arrived.
    fn list_labeled_containers(containers: &ReaperContainers, buffer: &mut [u8]) -> usize {
        let mut fds = [0 as libc::c_int; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return 0;
        }
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            close_fd(fds[0]);
            close_fd(fds[1]);
            return 0;
        }
        if pid == 0 {
            unsafe {
                // The reaper closed every inherited descriptor including 0, 1
                // and 2, so `pipe` may well have handed back fd 0 and fd 1
                // themselves. Move the write end onto stdout only when it is
                // not already there, and never close the descriptor that IS
                // stdout: doing so leaves `docker ps` writing to a closed fd,
                // the listing empty, and nothing reclaimed — with the reaper
                // reporting exactly the same success it reports on a clean
                // machine. Measured, not reasoned: it is what happened.
                if fds[1] != 1 && libc::dup2(fds[1], 1) < 0 {
                    libc::_exit(127);
                }
                if fds[0] != 1 {
                    close_fd(fds[0]);
                }
                if fds[1] != 1 {
                    close_fd(fds[1]);
                }
                quiet_standard_descriptors();
                libc::execv(containers.program.as_ptr(), containers.ps_argv.as_ptr());
                libc::_exit(127);
            }
        }
        close_fd(fds[1]);
        let filled = read_bounded(fds[0], buffer);
        close_fd(fds[0]);
        reap_bounded(pid);
        filled
    }

    /// `docker <verb> <id>`, output discarded, bounded.
    fn spawn_docker(program: *const libc::c_char, argv: *const *const libc::c_char) {
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return;
        }
        if pid == 0 {
            unsafe {
                quiet_standard_descriptors();
                libc::execv(program, argv);
                libc::_exit(127);
            }
        }
        reap_bounded(pid);
    }

    /// Give the exec'd `docker` real standard descriptors.
    ///
    /// The reaper closed every inherited descriptor including 0, 1 and 2, so
    /// without this a `docker` that opened a file would be handed **fd 1 or fd
    /// 2** for it and would then write its output or its diagnostics into that
    /// file. `/dev/null` on whichever of the three is still free is the
    /// cheapest way to make the numbers mean what they mean.
    ///
    /// A descriptor that is **already** open is left alone, which is what keeps
    /// this from undoing the listing child's pipe on fd 1.
    unsafe fn quiet_standard_descriptors() {
        unsafe {
            // In this order: `open` returns the lowest free descriptor, so
            // filling 0 first is what lets 1 and 2 land where they are asked
            // for without a `dup2` at all.
            ensure_standard_descriptor(0, libc::O_RDONLY);
            ensure_standard_descriptor(1, libc::O_WRONLY);
            ensure_standard_descriptor(2, libc::O_WRONLY);
        }
    }

    /// Open `/dev/null` onto `target` unless something is already there.
    unsafe fn ensure_standard_descriptor(target: libc::c_int, flags: libc::c_int) {
        unsafe {
            if libc::fcntl(target, libc::F_GETFD) != -1 {
                return;
            }
            let opened = libc::open(c"/dev/null".as_ptr(), flags);
            if opened < 0 {
                return;
            }
            if opened != target {
                let _ = libc::dup2(opened, target);
                close_fd(opened);
            }
        }
    }

    /// Read until EOF, the buffer is full, or the ceiling is reached.
    fn read_bounded(fd: libc::c_int, buffer: &mut [u8]) -> usize {
        let mut used = 0_usize;
        let mut ticks = 0_usize;
        while used < buffer.len() {
            let mut waiting = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut waiting, 1, 10) };
            if ready < 0 {
                if last_errno_is_interrupted() {
                    continue;
                }
                return used;
            }
            if ready == 0 {
                ticks = ticks.saturating_add(1);
                if ticks >= REAPER_DOCKER_TICKS {
                    return used;
                }
                continue;
            }
            let read = unsafe {
                libc::read(
                    fd,
                    buffer.as_mut_ptr().add(used).cast(),
                    buffer.len() - used,
                )
            };
            if read > 0 {
                used += read as usize;
            } else if read < 0 && last_errno_is_interrupted() {
                continue;
            } else {
                return used;
            }
        }
        used
    }

    /// Wait for one `docker`, and kill it rather than hold R28 for ever.
    fn reap_bounded(pid: libc::pid_t) {
        for _ in 0..REAPER_DOCKER_TICKS {
            let waited = unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
            if waited == pid {
                return;
            }
            if waited < 0 && !last_errno_is_interrupted() {
                return;
            }
            raw_sleep_10ms();
        }
        unsafe {
            let _ = libc::kill(pid, libc::SIGKILL);
        }
        loop {
            let waited = unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
            if waited == pid || (waited < 0 && !last_errno_is_interrupted()) {
                return;
            }
        }
    }

    /// What a reaper does when its **coordinator has died**: settle the group,
    /// then close the container half of the orphan window.
    ///
    /// Separate from the [`REAPER_CLEANUP`] path on purpose, and this is the
    /// distinction the whole extension turns on. `REAPER_CLEANUP` and
    /// [`REAPER_CANCEL`] are the **live** coordinator asking for its invocation
    /// to be settled; killing its labeled containers there would kill the
    /// containers of a coordinator that is still spending through them, which is
    /// `authoritative_state`'s "a live incarnation's containers must not be
    /// touched" — the opposite of what this exists for.
    fn settle_after_coordinator_death(
        pgid: i32,
        anchor: libc::pid_t,
        cleanup_delay_ms: u64,
        containers: Option<&ReaperContainers>,
    ) {
        if pgid > 0 {
            cleanup_reaper_group(pgid, anchor, cleanup_delay_ms);
        }
        if let Some(containers) = containers {
            reclaim_labeled_containers(containers);
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::process::{Command, Stdio};
        use std::time::Instant;

        static REAPED_CHILD_STOP: AtomicBool = AtomicBool::new(false);

        /// R28 is a **shared** hold, and one run has more than one reaper.
        ///
        /// `resource_accounting.rows[R28].resource` — "a surviving Unix cleanup
        /// reaper's shared `cleanup.lock` hold (**one per reaper**; a reaper
        /// may outlive the coordinator while it settles its process groups)".
        /// Narrowing this `flock` to `LOCK_EX` would let the first reaper of a
        /// run take the hold and refuse every later one — the second concurrent
        /// invocation failing to start at all — and nothing observed it,
        /// because no test ran two overlapping invocations and inspected their
        /// holds.
        ///
        /// `flock` holds belong to the open file description, so two calls here
        /// are exactly two independent holders, which is what a second reaper
        /// is. The expected behaviour is `flock(2)`'s, not this function's:
        /// shared holds coexist and both exclude the exclusive side.
        #[test]
        fn the_reapers_cleanup_hold_is_shared_between_overlapping_invocations() {
            use std::os::unix::ffi::OsStrExt;

            let path = std::env::temp_dir().join(format!(
                "tactus-r28-shared-{}-{}.lock",
                std::process::id(),
                crate::ulid::ulid()
            ));
            std::fs::write(&path, b"").expect("create a cleanup lease file");
            let target = std::ffi::CString::new(path.as_os_str().as_bytes())
                .expect("a temporary path without a null byte");
            let held = std::slice::from_ref(&target);

            assert!(
                lock_cleanup_paths(held),
                "the first invocation's reaper could not take R28 at all"
            );
            assert!(
                lock_cleanup_paths(held),
                "a second overlapping invocation's reaper was refused the shared hold: \
                 R28 is `one per reaper`, not one per run"
            );

            // And both holds still exclude the next coordinator, which is the
            // other half of R28: `observed (never owned or reset) by the next
            // coordinator … through the exclusive cleanup probe`.
            // SAFETY: a null-terminated path this test created; a failure
            // returns a negative descriptor.
            let fd = unsafe { libc::open(target.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
            assert!(fd >= 0, "reopening the lease file");
            // SAFETY: `fd` is live and owned here until it is closed.
            let exclusive = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
            let errno = last_errno();
            close_fd(fd);
            let _ = std::fs::remove_file(&path);
            assert_ne!(
                exclusive, 0,
                "the exclusive side was granted while two reapers held R28"
            );
            assert!(
                errno == libc::EWOULDBLOCK || errno == libc::EAGAIN,
                "the exclusive probe failed for an unrelated reason: {errno}"
            );
        }

        #[test]
        fn reaper_distinguishes_a_probe_pulse_from_a_stable_parent_resume() {
            let mut running_polls = 0;
            for _ in 1..REAPER_RESUME_STABLE_POLLS {
                assert!(!parent_has_stably_resumed(Some(false), &mut running_polls));
            }
            assert!(!parent_has_stably_resumed(Some(true), &mut running_polls));
            assert_eq!(running_polls, 0);

            for _ in 1..REAPER_RESUME_STABLE_POLLS {
                assert!(!parent_has_stably_resumed(Some(false), &mut running_polls));
            }
            assert!(parent_has_stably_resumed(Some(false), &mut running_polls));
            assert!(!parent_has_stably_resumed(None, &mut running_polls));
            assert_eq!(running_polls, 0);
        }

        extern "C" fn reap_child_transitions(_: libc::c_int) {
            if REAPED_CHILD_STOP.swap(true, Ordering::SeqCst) {
                return;
            }
            let mut status = 0;
            let child = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG | libc::WUNTRACED) };
            if child > 0 && libc::WIFSTOPPED(status) {
                // Keep a broken implementation from leaking the consumed,
                // permanently stopped anchor after this regression fails.
                let _ = unsafe { libc::kill(child, libc::SIGKILL) };
            }
        }

        #[test]
        #[ignore = "subprocess helper"]
        fn sigchld_reaper_host_helper() {
            if std::env::var_os("TACTUS_SIGCHLD_REAPER_HELPER").is_none() {
                return;
            }
            REAPED_CHILD_STOP.store(false, Ordering::SeqCst);
            assert_ne!(
                unsafe {
                    libc::signal(
                        libc::SIGCHLD,
                        reap_child_transitions as *const () as libc::sighandler_t,
                    )
                },
                libc::SIG_ERR
            );
            let target = unsafe { libc::fork() };
            if target == 0 {
                let _ = unsafe { libc::setpgid(0, 0) };
                loop {
                    unsafe { libc::pause() };
                }
            }
            assert!(target > 0);
            let result = unsafe { libc::setpgid(target, target) };
            assert!(
                result == 0 || matches!(last_errno(), libc::EACCES | libc::EPERM),
                "setpgid: {}",
                std::io::Error::last_os_error()
            );

            let reaper = spawn_reaper().expect("spawn private reaper");
            assert!(reaper.register_raw(target), "register target group");
            assert!(reaper.cleanup(target), "cleanup target group");
            let _ = unsafe { libc::waitpid(target, std::ptr::null_mut(), 0) };
        }

        #[test]
        fn a_host_sigchld_reaper_cannot_consume_the_private_anchor() {
            use std::os::unix::process::CommandExt;

            let mut command = Command::new(std::env::current_exe().expect("test executable"));
            command
                .args(["sigchld_reaper_host_helper", "--ignored", "--nocapture"])
                .env("TACTUS_SIGCHLD_REAPER_HELPER", "1")
                .process_group(0)
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let mut child = command.spawn().expect("spawn SIGCHLD helper");
            let pid = i32::try_from(child.id()).expect("helper pid");
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if let Some(status) = child.try_wait().expect("poll SIGCHLD helper") {
                    assert!(status.success(), "SIGCHLD helper status: {status}");
                    break;
                }
                if Instant::now() >= deadline {
                    let _ = unsafe { libc::kill(-pid, libc::SIGKILL) };
                    let _ = child.wait();
                    panic!("inherited SIGCHLD reaper consumed the private anchor transition");
                }
                thread::sleep(Duration::from_millis(10));
            }
        }

        #[cfg(target_os = "linux")]
        #[test]
        #[ignore = "subprocess helper"]
        fn linux_close_range_fd_zero_helper() {
            if std::env::var_os("TACTUS_CLOSE_RANGE_FD_ZERO_HELPER").is_none() {
                return;
            }

            // The Rust test harness may reopen a missing standard descriptor
            // during startup, so close it at the final isolated point before
            // the pipe that must receive fd zero.
            let closed = unsafe { libc::close(libc::STDIN_FILENO) };
            assert!(
                closed == 0 || last_errno() == libc::EBADF,
                "closing helper stdin: {}",
                std::io::Error::last_os_error()
            );
            let mut pipe = [-1; 2];
            assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
            assert_eq!(pipe[0], 0, "closed stdin was not reused as pipe fd zero");
            let open_max = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
            assert!(open_max > 0, "invalid open-file descriptor ceiling");
            let open_max = libc::c_int::try_from(open_max).expect("descriptor ceiling fits c_int");

            close_inherited_fds(
                &[pipe[0], pipe[1], libc::STDOUT_FILENO, libc::STDERR_FILENO],
                open_max,
            );
            let sent = [0x5a_u8];
            let mut received = [0_u8];
            assert!(write_raw(pipe[1], &sent), "write through kept pipe");
            assert!(
                read_raw_exact(pipe[0], &mut received),
                "close_range closed kept fd zero"
            );
            assert_eq!(received, sent);
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn linux_close_range_preserves_a_kept_fd_zero() {
            let mut command = Command::new(std::env::current_exe().expect("test executable"));
            command
                .args([
                    "linux_close_range_fd_zero_helper",
                    "--ignored",
                    "--nocapture",
                ])
                .env("TACTUS_CLOSE_RANGE_FD_ZERO_HELPER", "1")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let output = command.output().expect("run fd-zero close-range helper");
            assert!(
                output.status.success(),
                "fd-zero helper failed: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        #[test]
        fn a_launch_cannot_enter_after_the_suspend_snapshot() {
            let state = Arc::new(Mutex::new(State {
                spawning: 0,
                groups: vec![RegisteredGroup {
                    pgid: 41,
                    signal_leases: 0,
                }],
                terminating: false,
                suspending: false,
                guard: Guard {
                    command_fd: -1,
                    ack_fd: -1,
                    _command_keepalive_fd: -1,
                    pid: -1,
                },
            }));
            let (groups, _) = begin_suspend(&state).expect("begin suspend transition");
            assert_eq!(&*groups, &[41]);

            let waiting = Arc::clone(&state);
            let (sent, received) = std::sync::mpsc::channel();
            let launch = thread::spawn(move || {
                // Exercise the production launch gate without fabricating a
                // second independent cleanup-reaper registry. Production has
                // one shared registry and serializes helper creation through
                // this claim; constructing a private Supervisor here violates
                // that invariant and makes Darwin FIFO inheritance part of a
                // synchronization test that never intended to cover it.
                claim_launch(&waiting).expect("launch after resume");
                sent.send(()).expect("report launch");
                release_launch(&waiting);
            });
            assert!(
                received.recv_timeout(Duration::from_millis(50)).is_err(),
                "a launch entered while the frozen process-group snapshot was active"
            );

            let resumed = end_suspend(&state);
            assert_eq!(&*resumed, &[41]);
            drop(resumed);
            drop(groups);
            received
                .recv_timeout(Duration::from_secs(2))
                .expect("launch released after resume");
            launch.join().expect("join launch");
            let locked = state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            assert_eq!(locked.spawning, 0);
        }

        #[test]
        fn signal_snapshot_pins_a_group_until_delivery_finishes() {
            let state = Arc::new(Mutex::new(State {
                spawning: 0,
                groups: vec![RegisteredGroup {
                    pgid: 41,
                    signal_leases: 0,
                }],
                terminating: false,
                suspending: false,
                guard: Guard {
                    command_fd: -1,
                    ack_fd: -1,
                    _command_keepalive_fd: -1,
                    pid: -1,
                },
            }));
            let snapshot = groups_when_registered(&state, false).expect("group snapshot");
            {
                let mut locked = state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                assert_eq!(locked.groups[0].signal_leases, 1);
                assert!(
                    !remove_unpinned_group(&mut locked, 41),
                    "finish exposed the group id while a signal snapshot held it"
                );
            }
            drop(snapshot);
            let mut locked = state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            assert!(remove_unpinned_group(&mut locked, 41));
            assert!(locked.groups.is_empty());
        }

        #[test]
        fn helper_pipe_descriptors_are_close_on_exec() {
            let pipe = create_cloexec_pipe().expect("atomic close-on-exec pipe");
            for fd in pipe {
                let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
                assert!(flags >= 0, "read descriptor flags");
                assert_ne!(
                    flags & libc::FD_CLOEXEC,
                    0,
                    "helper descriptor was visible without close-on-exec"
                );
                close_fd(fd);
            }
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn linux_stat_parser_handles_spaces_and_closing_parentheses_in_comm() {
            let stat = "123 (reviewer ) helper) T 7 123 123 0 -1 0";
            assert_eq!(parse_linux_process_stat(stat), Some((123, b'T')));
            assert_eq!(parse_linux_stat_bytes(stat.as_bytes()), Some((123, b'T')));
            assert_eq!(parse_linux_process_stat("malformed"), None);
            assert_eq!(parse_linux_stat_bytes(b"malformed"), None);
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn a_vanished_linux_pid_is_not_an_incomplete_scanner_snapshot() {
            assert_eq!(read_linux_stat_raw(i32::MAX), LinuxStatSnapshot::Vanished);
        }

        #[test]
        fn a_zombie_only_group_is_quiescent_for_cleanup() {
            // SAFETY: the child performs only async-signal-safe syscalls and
            // exits immediately. The parent deliberately observes it without
            // reaping so the cleanup scanner sees a real zombie-only PGID.
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                let code = i32::from(unsafe { libc::setpgid(0, 0) } != 0);
                unsafe { libc::_exit(code) };
            }
            assert!(pid > 0, "fork failed: {}", std::io::Error::last_os_error());

            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            loop {
                let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                let result = unsafe {
                    libc::waitid(
                        libc::P_PID,
                        pid as libc::id_t,
                        &mut info,
                        libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                    )
                };
                assert_eq!(result, 0, "waitid: {}", std::io::Error::last_os_error());
                if unsafe { info.si_pid() } == pid {
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "child never became a zombie"
                );
                thread::sleep(Duration::from_millis(1));
            }

            // An unrelated process can disappear between `/proc` enumeration
            // and its stat read, making one conservative scanner snapshot
            // unknown. Cleanup retries that state; this regression must model
            // the same contract rather than requiring an unrealistically
            // quiescent runner on its first snapshot.
            let scan_deadline = std::time::Instant::now() + Duration::from_secs(2);
            let observed = loop {
                match group_has_non_zombie_members(pid) {
                    observed @ Some(_) => break observed,
                    None if std::time::Instant::now() < scan_deadline => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    None => break None,
                }
            };
            unsafe {
                let _ = libc::waitpid(pid, std::ptr::null_mut(), 0);
            }
            assert_eq!(observed, Some(false));
        }
    }
}

/// A pipe reader whose buffer can be snapshotted without joining the thread,
/// so an orphan holding the write end can never stall the supervisor.
struct Drain {
    buf: Arc<Mutex<Vec<u8>>>,
    limited: Arc<AtomicBool>,
    handle: thread::JoinHandle<()>,
}

impl Drain {
    fn start<R: Read + Send + 'static>(mut pipe: R, limit: usize) -> Self {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let writer = Arc::clone(&buf);
        let limited = Arc::new(AtomicBool::new(false));
        let reader_limited = Arc::clone(&limited);
        let handle = thread::spawn(move || {
            let mut chunk = [0u8; 8192];
            loop {
                match pipe.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let mut guard = match writer.lock() {
                            Ok(guard) => guard,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                        let remaining = limit.saturating_sub(guard.len());
                        let retained = remaining.min(n);
                        guard.extend_from_slice(&chunk[..retained]);
                        if retained < n {
                            reader_limited.store(true, Ordering::SeqCst);
                        }
                    }
                }
            }
        });
        Self {
            buf,
            limited,
            handle,
        }
    }

    fn limit_exceeded(&self) -> bool {
        self.limited.load(Ordering::SeqCst)
    }

    /// Wait up to `grace` for EOF, then snapshot whatever arrived. A reader
    /// abandoned here exits on its own when the last write handle closes.
    fn collect(self, grace: Duration) -> (String, bool) {
        let deadline = Instant::now() + grace;
        while !self.handle.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        if self.handle.is_finished() {
            let _ = self.handle.join();
        }
        let snapshot = match self.buf.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        (
            String::from_utf8_lossy(&snapshot).into_owned(),
            self.limited.load(Ordering::SeqCst),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A memoised establishment failure is reported to **every** later caller.
    ///
    /// `crash_reconstruction`: "if the ambient job cannot be created or joined
    /// the write command refuses at startup with a diagnostic before any
    /// workspace effect (**no degraded mode**; deferred)". The memo makes the
    /// first caller's answer every caller's answer, so an arm that turned a
    /// remembered failure back into success is a degraded mode that no later
    /// call can escape (`PR5-CORRECTNESS-010`).
    ///
    /// Runs on every platform, deliberately. The value is Windows-only; the
    /// decision about it is not, and before this the only machine that could
    /// have executed the failing arm was one where the arm was unreachable —
    /// a process that memoised a failure never got a coordinator to observe it
    /// with.
    #[test]
    fn a_memoised_establishment_failure_reaches_every_later_caller() {
        // The success arm, so this is not a test that only ever says "Err".
        assert_eq!(memoised_outcome::<()>(&Ok(())), Ok(()));

        // The failure arm, and the diagnostic is the memo's own: the caller
        // renders it into the operator-facing refusal, so a fresh or empty
        // message would name something that did not happen.
        for message in [
            "it could not be created (Access is denied. (os error 5))",
            "it could not be configured (os error 87)",
            "AssignProcessToJobObject refused",
        ] {
            assert_eq!(
                memoised_outcome::<()>(&Err(message.to_owned())),
                Err(message.to_owned()),
                "a remembered failure must come back as that failure"
            );
        }

        // And it is stable: the *second* caller gets the same answer as the
        // first, which is the whole of what a memo promises.
        let memo: Result<(), String> = Err("it could not be created".to_owned());
        assert_eq!(memoised_outcome(&memo), memoised_outcome(&memo));
        assert!(memoised_outcome(&memo).is_err());
    }

    // Windows-first-class: exercise the supervisor through cmd.exe, which is
    // always present there; use sh on everything else.
    fn shell(script: &str) -> Command {
        if cfg!(windows) {
            let mut c = Command::new("cmd");
            c.args(["/C", script]);
            c
        } else {
            let mut c = Command::new("sh");
            c.args(["-c", script]);
            c
        }
    }

    #[test]
    fn captures_stdout_and_exit_code() {
        let out = run_with_timeout(shell("echo hello"), "", Duration::from_secs(30))
            .expect("spawn shell");
        assert_eq!(out.code, Some(0));
        assert!(out.stdout.contains("hello"));
        assert!(!out.timed_out);
        assert!(!out.output_limited);
    }

    /// Writes `TACTUS_EXCESSIVE_OUTPUT_HELPER` bytes to stdout, then exits.
    ///
    /// **Bounded, and the bound is the point.** This used to be `loop { write }`,
    /// which is harmless while the funnel bounds capture: the parent stops
    /// reading at the allowance, the child blocks on a full pipe, and the tree
    /// is killed long before any budget matters. But the test that exists to
    /// catch an *unbounded* allowance —
    /// [`crate::runner::host::tests::the_runner_bounds_output_at_the_same_allowance_the_direct_funnel_does`]
    /// — then had no failure mode except memory exhaustion. Measured under
    /// `PR4-CORRECTNESS-004`'s own mutation (`OUTPUT_LIMIT_BYTES` ->
    /// `usize::MAX`): the parent captured until the OOM killer took the whole
    /// test binary, so the witness arrived as `signal: 9` attributed to an
    /// unrelated test, with 900-odd tests never run and no `test result:` line
    /// at all. A witness that destroys the evidence it is producing is not a
    /// witness.
    ///
    /// A finite budget several times the real allowance keeps both readings.
    /// A funnel that bounds correctly still kills a child blocked on a full
    /// pipe well before the budget is written, so nothing about the passing
    /// case changes; a funnel that does not bound captures a large but
    /// survivable amount, the child exits 0, and the assertion that fails is
    /// `output_limited`, by name.
    #[test]
    #[ignore = "subprocess helper"]
    fn excessive_output_helper() {
        let Some(budget) = std::env::var_os("TACTUS_EXCESSIVE_OUTPUT_HELPER") else {
            return;
        };
        let budget: usize = budget
            .to_string_lossy()
            .parse()
            .expect("the helper's byte budget");
        let chunk = [b'x'; 4096];
        // Which stream, because the allowance is **per stream** and every
        // fixture used to fill only one of them: a check that never looked at
        // stderr was indistinguishable from this one.
        let on_stderr = std::env::var_os("TACTUS_EXCESSIVE_OUTPUT_STREAM")
            .is_some_and(|stream| stream == "stderr");
        let mut stdout = std::io::stdout().lock();
        let mut stderr = std::io::stderr().lock();
        let mut written = 0_usize;
        while written < budget {
            let sink: &mut dyn Write = if on_stderr { &mut stderr } else { &mut stdout };
            sink.write_all(&chunk)
                .expect("write deterministic excessive output");
            written += chunk.len();
        }
        // Written the budget, and still alive.
        //
        // The budget alone is not enough: 64 MiB crosses a pipe in well under
        // a second, so a child that exited here would often be *gone* before
        // the supervisor acted on the allowance, and the funnel would report
        // `code: Some(0)` with the limit observed during the final drain —
        // a real behaviour, but not the one the two callers assert. Staying
        // alive keeps "an output-limited tree is terminated, not exited" true
        // for a funnel that bounds, while a funnel that does *not* bound still
        // reaches this line with a bounded amount captured and then exits, so
        // its witness is an assertion rather than an OOM.
        thread::sleep(Duration::from_secs(15));
    }

    /// What this module's output-limit test gives the helper: comfortably more
    /// than the allowance under test, and small enough to hold in memory if
    /// the allowance stops working.
    ///
    /// `runner::host`'s test declares its own, deliberately: a budget below
    /// the allowance it is testing makes that test's own `output_limited`
    /// assertion fail, so each budget is checked by the test that sets it and
    /// there is nothing for a shared constant to keep in step.
    const EXCESSIVE_OUTPUT_BUDGET: usize = 64 * 1024 * 1024;

    #[test]
    fn excessive_output_is_bounded_and_terminates_the_tree() {
        const TEST_LIMIT: usize = 64 * 1024;
        let mut command = Command::new(std::env::current_exe().expect("test executable"));
        command
            .args(["excessive_output_helper", "--ignored", "--nocapture"])
            .env(
                "TACTUS_EXCESSIVE_OUTPUT_HELPER",
                EXCESSIVE_OUTPUT_BUDGET.to_string(),
            );

        let started = Instant::now();
        let out = run_with_timeout_and_limit(
            command,
            b"",
            Duration::from_secs(30),
            TEST_LIMIT,
            &mut NoHooks,
        )
        .expect("supervise noisy child");
        assert!(out.output_limited, "supervised output: {out:?}");
        assert!(!out.timed_out);
        assert!(out.code.is_none());
        assert!(out.stdout.len() <= TEST_LIMIT);
        assert!(out.stderr.len() <= TEST_LIMIT);
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "output-limited child was not terminated promptly: {:?}",
            started.elapsed()
        );
    }

    /// The allowance is **per stream**, and stderr is a stream.
    ///
    /// Every output-limit fixture in this suite filled stdout, so a check that
    /// never looked at stderr behaved exactly like this one: an agent that
    /// writes its diagnostics to stderr — which is where a CLI writes them —
    /// could fill memory without ever tripping the bound.
    /// `invariants_preserved[0]` is "output capture … unchanged", and the
    /// bounded half of that is what this asks about.
    #[test]
    fn the_output_allowance_bounds_stderr_as_well_as_stdout() {
        const TEST_LIMIT: usize = 64 * 1024;

        // The negative control first: a small writer on the same stream is not
        // limited, so `output_limited` below is the size and not the stream.
        let small = run_with_timeout_and_limit(
            shell("echo problem 1>&2"),
            b"",
            Duration::from_secs(60),
            TEST_LIMIT,
            &mut NoHooks,
        )
        .expect("supervise a modest stderr writer");
        assert!(
            !small.output_limited,
            "a small writer was limited: {small:?}"
        );
        assert!(
            small.stderr.contains("problem"),
            "the control fixture wrote nothing to stderr: {small:?}"
        );

        let mut command = Command::new(std::env::current_exe().expect("test executable"));
        command
            .args(["excessive_output_helper", "--ignored", "--nocapture"])
            .env(
                "TACTUS_EXCESSIVE_OUTPUT_HELPER",
                EXCESSIVE_OUTPUT_BUDGET.to_string(),
            )
            .env("TACTUS_EXCESSIVE_OUTPUT_STREAM", "stderr");
        let started = Instant::now();
        let out = run_with_timeout_and_limit(
            command,
            b"",
            Duration::from_secs(60),
            TEST_LIMIT,
            &mut NoHooks,
        )
        .expect("supervise a noisy stderr child");
        assert!(
            out.output_limited,
            "a stderr-only producer was never bounded: {out:?}"
        );
        // `output_limited` alone is **not** the property, and measuring it
        // alone let the first version of this test pass under the mutation it
        // exists for: the final drain sets that flag from `stderr_limited`
        // whatever the supervisor did, so a limit check that never looked at
        // stderr still reported the overrun — after letting the child run to
        // completion. The property is that the tree is *terminated* at the
        // allowance, which is an exit code that is not the child's and a
        // return that does not wait for it.
        assert!(
            out.code.is_none(),
            "the stderr-limited child exited on its own terms rather than \
             being terminated: {out:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the stderr-limited tree was not terminated promptly: {:?}",
            started.elapsed()
        );
        assert!(!out.timed_out, "{out:?}");
        assert!(out.stderr.len() <= TEST_LIMIT, "{}", out.stderr.len());
        assert!(
            !out.stdout.contains("xxxx"),
            "the stderr fixture wrote its payload to stdout, so the bound this \
             test observed was stdout's after all"
        );
    }

    /// Stdin is **bytes**, and arrives byte for byte.
    ///
    /// `CommandSpec { … stdin: Vec<u8> }` (DESIGN.md:222) is a byte field, and
    /// every stdin fixture in this suite is valid UTF-8 text — so a lossy
    /// conversion on the way to the child changes nothing any of them can see,
    /// while an agent handed binary input on stdin would silently receive
    /// `U+FFFD` where its bytes used to be.
    ///
    /// The child reports what it received in hex, so the comparison is against
    /// the bytes this test wrote and not against a string round trip.
    #[test]
    #[ignore = "subprocess helper"]
    fn stdin_hex_helper() {
        if std::env::var_os("TACTUS_STDIN_HEX").is_none() {
            return;
        }
        let mut received = Vec::new();
        std::io::stdin()
            .read_to_end(&mut received)
            .expect("read stdin");
        let mut hex = String::new();
        for byte in &received {
            hex.push_str(&format!("{byte:02x}"));
        }
        print!("<{hex}>");
        let _ = std::io::stdout().flush();
    }

    #[test]
    fn stdin_reaches_the_child_byte_for_byte() {
        // Not valid UTF-8: a lone 0x80 continuation, a 0xff that no encoding
        // produces, and a NUL — every one of which `from_utf8_lossy` replaces.
        let payload: Vec<u8> = vec![0x00, 0x80, 0xff, 0x0a, 0x41];
        assert_ne!(
            String::from_utf8_lossy(&payload).as_bytes(),
            payload.as_slice(),
            "the fixture must be bytes a lossy conversion would change, or the \
             mutation this test exists for is invisible to it too"
        );
        let mut command = Command::new(std::env::current_exe().expect("test executable"));
        command
            .args(["stdin_hex_helper", "--ignored", "--nocapture"])
            .env("TACTUS_STDIN_HEX", "1");
        let out = run_with_timeout_hooked(command, &payload, Duration::from_secs(60), &mut NoHooks)
            .expect("supervise the stdin helper");
        let expected: String = payload.iter().map(|byte| format!("{byte:02x}")).collect();
        assert!(
            out.stdout.contains(&format!("<{expected}>")),
            "the child did not receive the bytes this test wrote: {} (wanted {expected})",
            out.stdout
        );
    }

    /// A timed-out attempt keeps the transcript it produced.
    ///
    /// §14 makes the partial transcript the retry's feedback, and
    /// `invariants_preserved[0]` keeps "output capture … unchanged". The one
    /// timing-out fixture in this suite is `sleep 30`, which writes nothing
    /// before it is killed — so discarding the whole transcript on timeout was
    /// a no-op on every fixture that reaches the branch.
    #[test]
    #[ignore = "subprocess helper"]
    fn timeout_transcript_helper() {
        if std::env::var_os("TACTUS_TIMEOUT_TRANSCRIPT").is_none() {
            return;
        }
        print!("OUT-BEFORE-TIMEOUT");
        let _ = std::io::stdout().flush();
        eprint!("ERR-BEFORE-TIMEOUT");
        let _ = std::io::stderr().flush();
        thread::sleep(Duration::from_secs(60));
    }

    #[test]
    fn a_timed_out_child_keeps_the_transcript_it_had_already_written() {
        let mut command = Command::new(std::env::current_exe().expect("test executable"));
        command
            .args(["timeout_transcript_helper", "--ignored", "--nocapture"])
            .env("TACTUS_TIMEOUT_TRANSCRIPT", "1");
        let out = run_with_timeout(command, "", Duration::from_secs(3))
            .expect("supervise the transcript helper");
        assert!(out.timed_out, "{out:?}");
        assert!(
            out.stdout.contains("OUT-BEFORE-TIMEOUT"),
            "the timed-out child's stdout was discarded: {:?}",
            out.stdout
        );
        assert!(
            out.stderr.contains("ERR-BEFORE-TIMEOUT"),
            "the timed-out child's stderr was discarded: {:?}",
            out.stderr
        );
    }

    /// The reaper knows the group **before** the parent registers it, because
    /// the child registered it before `exec`.
    ///
    /// `crash_reconstruction`: "Host, Unix: private process groups plus the
    /// per-invocation cleanup reaper **registered pre-exec inside the child**
    /// … leave no unregistered prefix". The existing pre-exec witness asks the
    /// kernel `getpgid(pid) == pid`, which proves `setpgid(0, 0)` ran and says
    /// nothing about the registration beside it — so moving the registration
    /// out of the `pre_exec` closure and into the parent's `register` left
    /// every test passing while re-opening the window the design closes: a
    /// coordinator SIGKILLed between `spawn` returning and parent-side
    /// registration leaves a running group no reaper will settle.
    ///
    /// The oracle is that window itself. The supervisor is dropped in exactly
    /// that state — child spawned, parent registration never performed — and
    /// the group has to be settled anyway. Everything the reaper can know here
    /// it learned from the child.
    #[cfg(unix)]
    #[test]
    // `try_wait` in the loop and `kill` + `wait` in the fallback do settle the
    // child on every path; the lint does not model `try_wait`.
    #[allow(clippy::zombie_processes)]
    fn a_child_registered_pre_exec_is_settled_when_the_parent_never_registers_it() {
        use std::os::unix::process::ExitStatusExt;

        let supervisor = termination::Supervisor::begin().expect("start a private reaper");
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "sleep 60"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        supervisor.prepare(&mut command);
        let mut child = command
            .spawn()
            .expect("spawn a child that outlives the parent's window");
        let pid = child.id();
        assert!(
            child_leads_its_own_group(pid),
            "the pre-exec closure did not run at all, so this witnesses nothing"
        );

        // Not registered by the parent: this is the prefix the packet says
        // must not exist unregistered. Dropping here is the coordinator dying
        // in that window, and `Drop` in the `Spawning` phase cancels the
        // reaper — which settles whatever the reaper knows about.
        drop(supervisor);

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut settled = None;
        while Instant::now() < deadline {
            match child.try_wait().expect("poll the child") {
                Some(status) => {
                    settled = Some(status);
                    break;
                }
                None => thread::sleep(Duration::from_millis(20)),
            }
        }
        let reaped_before_the_deadline = settled.is_some();
        if settled.is_none() {
            // Do not leak a 60-second sleeper into the rest of the suite when
            // this fails.
            let _ = child.kill();
            settled = child.wait().ok();
        }
        assert!(
            reaped_before_the_deadline,
            "the child's group outlived a cancelled reaper: nothing registered it, so the \
             registration is not happening in the child before exec"
        );
        let status = settled.expect("the child could not be waited on at all");
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "the group was settled by something other than the reaper: {status:?}"
        );
    }

    #[test]
    fn nonzero_exit_is_reported_not_an_error() {
        let out =
            run_with_timeout(shell("exit 3"), "", Duration::from_secs(30)).expect("spawn shell");
        assert_eq!(out.code, Some(3));
    }

    #[test]
    fn stdin_reaches_the_child() {
        let script = if cfg!(windows) { "findstr ping" } else { "cat" };
        let out = run_with_timeout(shell(script), "ping pong\n", Duration::from_secs(30))
            .expect("spawn shell");
        assert!(out.stdout.contains("ping"), "stdout: {}", out.stdout);
    }

    #[test]
    fn timeout_kills_the_process_tree_quickly() {
        // Through the shell, the sleeper is a grandchild — exactly the
        // claude.cmd shim shape this module must handle.
        let script = if cfg!(windows) {
            "ping -n 30 127.0.0.1 > NUL"
        } else {
            "sleep 30"
        };
        let started = Instant::now();
        let out =
            run_with_timeout(shell(script), "", Duration::from_millis(300)).expect("spawn shell");
        assert!(out.timed_out);
        assert!(out.code.is_none());
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "supervisor returned promptly, no orphan stall: {:?}",
            started.elapsed()
        );
    }

    #[cfg(unix)]
    #[test]
    fn timeout_kills_a_background_grandchild_before_it_can_escape() {
        let marker = std::env::temp_dir().join(format!(
            "tactus-proc-tree-{}-{}.marker",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        let _ = std::fs::remove_file(&marker);

        let mut command = shell("(sleep 1; printf leaked > \"$TACTUS_MARKER\") & wait");
        command.env("TACTUS_MARKER", &marker);
        let out = run_with_timeout(command, "", Duration::from_millis(200)).expect("spawn shell");
        assert!(out.timed_out);

        thread::sleep(Duration::from_millis(1300));
        let leaked = marker.exists();
        let _ = std::fs::remove_file(&marker);
        assert!(
            !leaked,
            "the timed-out process group's background grandchild survived"
        );
    }

    /// Whether every writer of `fd`'s pipe is gone, asked of the kernel and
    /// answered now.
    ///
    /// A dead process holds no descriptors, so an immediate `EOF` from a
    /// non-blocking read is exactly "nothing that inherited this pipe is still
    /// running" — and unlike `kill(pid, 0)` it is not answered `Ok` by a
    /// zombie waiting for its reparented reaper. `EAGAIN` is the other answer:
    /// somebody still holds the write end.
    ///
    /// **Bytes are not an answer, so they are drained rather than counted.**
    /// `read` returns how many bytes it moved, and this used to compare that
    /// against zero: one byte of anything on the child's stderr — a shell
    /// diagnostic, a linker warning, a locale complaint, none of which this
    /// fixture controls on every platform — then reads as "a writer is still
    /// there" for as long as the byte sits in the pipe, which is forever. EOF
    /// is a property of the pipe once it is empty, so emptying it first is
    /// what makes this question the one the caller means.
    #[cfg(unix)]
    fn every_pipe_writer_is_gone(fd: libc::c_int) -> bool {
        let mut buffer = [0_u8; 256];
        loop {
            // SAFETY: `fd` is a live non-blocking read end owned by this test
            // and `buffer` is a writable buffer of the length passed.
            let read = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
            match read {
                // EOF: no descriptor for the write end exists anywhere.
                0 => return true,
                // Somebody wrote. Not an answer either way — drain and re-ask.
                1.. => (),
                // `EAGAIN` (a writer holds it) or `EINTR` (ask again later).
                _ => return false,
            }
        }
    }

    /// `kill_tree` settles the child's whole **group**, and does it before it
    /// returns.
    ///
    /// This is the one path on Unix that reaches `kill_tree`, and no test drove
    /// it: the explicit `kill(-pgid, SIGKILL)` could be deleted outright and
    /// the suite stayed green, because everywhere the funnel *is* exercised the
    /// per-invocation reaper settles the same group and either mechanism alone
    /// satisfies every assertion. Nothing here starts a reaper, so `kill_tree`
    /// is the only thing that can settle this group — which is what tells the
    /// two apart.
    ///
    /// The oracle is `kill_tree`'s own doc comment turned into a question:
    /// "the real agent process would survive, keep running, and **keep the
    /// pipes open**". A group member that outlived the call still holds the
    /// inherited stderr, so the read end is not at EOF.
    #[cfg(unix)]
    #[test]
    fn kill_tree_settles_the_whole_unix_group_before_it_returns() {
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;

        let scratch = std::env::temp_dir().join(format!(
            "tactus-kill-tree-{}-{}",
            std::process::id(),
            crate::ulid::ulid()
        ));
        std::fs::create_dir_all(&scratch).expect("scratch directory");
        let ready = scratch.join("ready");
        let mut command = shell("sh -c 'printf ready > \"$TACTUS_READY\"; sleep 60' & sleep 60");
        command
            .env("TACTUS_READY", &ready)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        // SAFETY: the closure calls one async-signal-safe syscall. The group is
        // what `kill_tree` targets, so the fixture must have one of its own.
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut tree =
            ProcessTree::spawn(&mut command, &mut NoHooks).expect("spawn a group leader");
        let pgid = i32::try_from(tree.child.id()).expect("pid fits");
        let stderr = tree.child.stderr.take().expect("piped stderr");
        let fd = stderr.as_raw_fd();
        // SAFETY: `fd` is owned by `stderr`, which outlives this call.
        unsafe {
            libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(ready.exists(), "the grandchild never started");
        assert!(
            !every_pipe_writer_is_gone(fd),
            "the fixture holds no pipe, so this test would pass vacuously"
        );

        kill_tree(&mut tree).expect("settle the group");
        // Bounded rather than instantaneous, and the bound is the kernel's:
        // `kill(-pgid, SIGKILL)` returns as soon as the signals are queued, so
        // a member can still be tearing down when this line runs. What the
        // bound cannot absorb is a member that was never signalled — the
        // fixture's survivors sleep for a minute.
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut settled = every_pipe_writer_is_gone(fd);
        while !settled && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
            settled = every_pipe_writer_is_gone(fd);
        }
        // SAFETY: a negative pid names the group; this is cleanup for the
        // failing case and a no-op for the passing one.
        unsafe {
            let _ = libc::kill(-pgid, libc::SIGKILL);
        }
        drop(stderr);
        drop(tree);
        let _ = std::fs::remove_dir_all(&scratch);
        assert!(
            settled,
            "kill_tree returned while a member of the child's process group was still \
             running and still holding its pipes: only the direct child was killed"
        );
    }

    /// A direct child that exits successfully does not leave its group behind.
    ///
    /// `successful_direct_exit_still_kills_detached_group_members` plants a
    /// detached grandchild and then sleeps 1.3 s before looking, so a
    /// settlement that happened *after* the supervisor returned would still
    /// pass it. This one asks inside the supervisor's own window: the
    /// grandchild writes to the inherited stdout after a second, and the
    /// funnel's post-exit drain grace is two, so a grandchild that outlived the
    /// return lands in the transcript the caller is given.
    #[cfg(unix)]
    #[test]
    fn a_successful_direct_exit_settles_its_group_before_the_transcript_is_collected() {
        let out = run_with_timeout(
            shell("sh -c 'sleep 1; printf ESCAPED' & exit 0"),
            "",
            Duration::from_secs(30),
        )
        .expect("spawn shell");
        assert_eq!(out.code, Some(0), "{out:?}");
        assert!(
            !out.stdout.contains("ESCAPED"),
            "a grandchild outlived the successful direct child and wrote into its \
             transcript: {}",
            out.stdout
        );
    }

    /// Every Unix containment point, measured against the operation it is named
    /// for rather than against the other points.
    ///
    /// The Unix half of the same gap: `containment_sub_effects` says "ST-07
    /// evidence executes each point **on its platform**", and the suite checked
    /// that these four exist, are declared Unix, and fire in the packet's order
    /// relative to each other — never that the thing each one is named for had
    /// happened. `ReaperStarted` says the per-invocation reaper is forked *and
    /// holding R28*; `PreExecPgidAndRegister` says the child leads its own
    /// group; `Registered` says the parent has it. Each could move to the wrong
    /// side of its own operation and stay green.
    ///
    /// The oracles are outside this crate wherever one exists: `getpgid` for
    /// the group (`child_leads_its_own_group`, already the pattern for one
    /// point and now for all of them) and `flock` for the hold — R28's own
    /// primitive, asked from the coordinator while the reaper owns it.
    #[cfg(unix)]
    #[test]
    fn every_unix_containment_point_is_measured_against_its_own_operation() {
        use std::os::unix::ffi::OsStrExt;
        use std::sync::{Arc, Mutex};

        #[derive(Debug, PartialEq, Eq)]
        struct Row {
            point: SubEffectPoint,
            /// Whether the child exists yet, from `child_created`.
            child_known: bool,
            /// `getpgid(pid) == pid`, or `None` before there is a pid.
            leads_own_group: Option<bool>,
            /// How many times this child's pgid appears in parent state.
            registered: usize,
            /// Whether an exclusive probe of R28 is refused right now.
            cleanup_hold_taken: bool,
        }

        #[derive(Clone)]
        struct Observer {
            pid: Arc<Mutex<Option<u32>>>,
            rows: Arc<Mutex<Vec<Row>>>,
            cleanup: std::ffi::CString,
        }

        impl Observer {
            /// Whether somebody holds R28 shared, asked with R28's own
            /// primitive from a descriptor this test opened.
            fn hold_taken(&self) -> bool {
                // SAFETY: a null-terminated path this test built; a failure
                // returns a negative descriptor.
                let fd =
                    unsafe { libc::open(self.cleanup.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
                if fd < 0 {
                    return false;
                }
                // SAFETY: `fd` is live and owned here until the close below.
                unsafe {
                    let free = libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) == 0;
                    if free {
                        let _ = libc::flock(fd, libc::LOCK_UN);
                    }
                    let _ = libc::close(fd);
                    !free
                }
            }
        }

        impl SpawnHooks for Observer {
            fn child_created(&mut self, pid: u32) {
                *self.pid.lock().expect("pid") = Some(pid);
            }

            fn point(&mut self, point: SubEffectPoint) -> Injection {
                let pid = *self.pid.lock().expect("pid");
                let pgid = pid.and_then(|pid| i32::try_from(pid).ok());
                let row = Row {
                    point,
                    child_known: pid.is_some(),
                    leads_own_group: pid.map(child_leads_its_own_group),
                    registered: pgid.map_or(0, |pgid| {
                        termination::registered_groups()
                            .iter()
                            .filter(|group| **group == pgid)
                            .count()
                    }),
                    cleanup_hold_taken: self.hold_taken(),
                };
                self.rows.lock().expect("rows").push(row);
                Injection::Proceed
            }
        }

        // A run directory with a live cleanup lease, so the reaper has an R28
        // to take. Without one `lock_cleanup_paths` is handed an empty list and
        // the hold this test is about does not exist.
        let public = std::env::temp_dir().join(format!(
            "tactus-r28-points-{}-{}",
            std::process::id(),
            crate::ulid::ulid()
        ));
        std::fs::create_dir_all(&public).expect("run directory");
        let lock = crate::rundir::RunLock::acquire(&public).expect("take the run lock");
        let scope = lock.enter_cleanup_scope();
        let paths = crate::rundir::active_cleanup_lease_paths();
        assert_eq!(
            paths.len(),
            1,
            "exactly one cleanup lease is active: {paths:?}"
        );
        let cleanup =
            std::ffi::CString::new(paths[0].as_os_str().as_bytes()).expect("path without a null");

        let observer = Observer {
            pid: Arc::new(Mutex::new(None)),
            rows: Arc::new(Mutex::new(Vec::new())),
            cleanup,
        };
        assert!(
            !observer.hold_taken(),
            "R28 is already held before the reaper exists, so this test proves nothing"
        );
        let mut hooks = observer.clone();
        let output =
            run_with_timeout_hooked(shell("exit 0"), b"", Duration::from_secs(30), &mut hooks)
                .expect("run through the funnel");
        assert_eq!(output.code, Some(0), "{output:?}");
        drop(scope);
        drop(lock);
        let _ = std::fs::remove_dir_all(&public);

        let observed = observer.rows.lock().expect("rows");
        let expected = vec![
            Row {
                point: SubEffectPoint::ReaperStarted,
                child_known: false,
                leads_own_group: None,
                registered: 0,
                cleanup_hold_taken: true,
            },
            Row {
                point: SubEffectPoint::PreExecPgidAndRegister,
                child_known: true,
                leads_own_group: Some(true),
                registered: 0,
                cleanup_hold_taken: true,
            },
            Row {
                point: SubEffectPoint::Exec,
                child_known: true,
                leads_own_group: Some(true),
                registered: 0,
                cleanup_hold_taken: true,
            },
            Row {
                point: SubEffectPoint::Registered,
                child_known: true,
                leads_own_group: Some(true),
                registered: 1,
                cleanup_hold_taken: true,
            },
        ];
        assert_eq!(
            *observed, expected,
            "a containment point no longer sits at the coordinate it names"
        );
    }

    /// Where the four Unix containment points are compiled in.
    ///
    /// `os_matrix` states the invariant for **all** Unix — "Linux and macOS
    /// (`cfg(unix)`): the cleanup reaper survives coordinator death, settles
    /// the dead coordinator's process groups while holding R28" — not for
    /// Linux. Narrowing any of these gates to `target_os = "linux"` would take
    /// macOS out of the containment contract, and no test on this box or on the
    /// Windows guest would notice: the emission would simply stop existing on a
    /// platform neither of them is. CI does run `macos-latest`, so this is an
    /// ordinary coverage gap rather than an unmeasurable one, and a census
    /// closes it without a macOS machine.
    ///
    /// The reaper's own `target_os` gates are a different thing and stay: the
    /// group scanner reads `/proc` on Linux and asks `/bin/ps` on macOS, which
    /// is two implementations of one behaviour, not one platform dropped.
    #[cfg(unix)]
    #[test]
    fn every_unix_containment_point_is_gated_on_unix_and_not_on_one_unix() {
        let source = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/agent/proc.rs"),
        )
        .expect("read the funnel's own source");
        let lines: Vec<&str> = source.lines().collect();

        let mut gates: Vec<(&str, &str)> = Vec::new();
        for (index, line) in lines.iter().enumerate() {
            const CALL: &str = "hooks.point(SubEffectPoint::";
            let Some(at) = line.find(CALL) else {
                continue;
            };
            let Some(point) = line[at + CALL.len()..].split(')').next() else {
                continue;
            };
            // The nearest preceding attribute is the gate this emission is
            // compiled behind.
            let gate = lines[..index]
                .iter()
                .rev()
                .find(|earlier| earlier.trim_start().starts_with("#[cfg("))
                .map(|earlier| earlier.trim())
                .unwrap_or("<none>");
            gates.push((point, gate));
        }

        let expected = vec![
            ("ReaperStarted", "#[cfg(unix)]"),
            ("PreExecPgidAndRegister", "#[cfg(unix)]"),
            ("Exec", "#[cfg(unix)]"),
            ("Registered", "#[cfg(unix)]"),
        ];
        let unix_gates: Vec<(&str, &str)> = gates
            .into_iter()
            .filter(|(point, _)| {
                matches!(
                    *point,
                    "ReaperStarted" | "PreExecPgidAndRegister" | "Exec" | "Registered"
                )
            })
            .collect();
        assert_eq!(
            unix_gates, expected,
            "a Unix containment point is compiled behind something other than \
             `cfg(unix)`; `os_matrix` says Linux **and macOS**"
        );
    }

    /// A disposable coordinator that leaves a non-`exec` fork holding the
    /// reaper's command pipe, then is hard-killed.
    ///
    /// The fork is the whole fixture: descriptors survive `fork` whether or not
    /// they are `CLOEXEC`, so this process's death closes no write end and the
    /// reaper never sees EOF. What it does see is reparenting.
    #[cfg(unix)]
    #[test]
    #[ignore = "subprocess helper"]
    #[allow(clippy::zombie_processes)]
    fn unix_reaper_reparent_helper() {
        if std::env::var_os("TACTUS_UNIX_REPARENT").is_none() {
            return;
        }
        let ready = std::path::PathBuf::from(std::env::var_os("TACTUS_READY").expect("ready path"));
        let agent = std::path::PathBuf::from(std::env::var_os("TACTUS_AGENT").expect("agent path"));
        let mut supervisor = termination::Supervisor::begin().expect("start a private reaper");
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "sleep 120"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        supervisor.prepare(&mut command);
        let child = command.spawn().expect("spawn an agent in its own group");
        supervisor
            .register(child.id())
            .expect("register the agent group");
        std::fs::write(&agent, child.id().to_string()).expect("record the agent pid");
        // SAFETY: the forked child calls only `sleep` and `_exit`, both
        // async-signal-safe, and never returns to the Rust runtime.
        let forked = unsafe { libc::fork() };
        if forked == 0 {
            unsafe {
                libc::sleep(120);
                libc::_exit(0);
            }
        }
        std::fs::write(&ready, forked.to_string()).expect("announce the pipe holder");
        thread::sleep(Duration::from_secs(120));
        // Unreachable in the fixture: the parent hard-kills this process.
        std::mem::forget(supervisor);
    }

    /// The reaper settles its group on **reparenting**, without waiting for the
    /// command pipe to close.
    ///
    /// `os_matrix`'s Unix half is stated for macOS as much as Linux, and on
    /// Darwin an exec-racing descendant can retain a pipe writer, so EOF is not
    /// a trustworthy parent-liveness signal — which is why `reaper_loop` polls
    /// `getppid()` at all. That check is invisible in every ordinary test
    /// because the coordinator's death closes the pipe too. Here a fork that
    /// never execs holds the write end open, so EOF never arrives and the
    /// reparenting check is the only thing that can settle the group.
    #[cfg(unix)]
    #[test]
    fn the_reaper_settles_its_group_on_reparenting_without_waiting_for_pipe_eof() {
        fn alive(pid: i32) -> bool {
            // SAFETY: signal 0 performs no delivery; it only asks whether the
            // pid can be signalled.
            unsafe { libc::kill(pid, 0) == 0 }
        }
        fn read_pid(path: &std::path::Path, timeout: Duration) -> i32 {
            let deadline = Instant::now() + timeout;
            loop {
                if let Ok(text) = std::fs::read_to_string(path) {
                    if let Ok(pid) = text.trim().parse() {
                        return pid;
                    }
                }
                assert!(
                    Instant::now() < deadline,
                    "{} never carried a pid",
                    path.display()
                );
                thread::sleep(Duration::from_millis(10));
            }
        }

        let scratch = std::env::temp_dir().join(format!(
            "tactus-reparent-{}-{}",
            std::process::id(),
            crate::ulid::ulid()
        ));
        std::fs::create_dir_all(&scratch).expect("scratch directory");
        let ready = scratch.join("ready");
        let agent = scratch.join("agent");
        let mut coordinator = Command::new(std::env::current_exe().expect("test executable"))
            .args(["unix_reaper_reparent_helper", "--ignored", "--nocapture"])
            .env("TACTUS_UNIX_REPARENT", "1")
            .env("TACTUS_READY", &ready)
            .env("TACTUS_AGENT", &agent)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn a disposable coordinator");
        let holder = read_pid(&ready, Duration::from_secs(20));
        let agent_pid = read_pid(&agent, Duration::from_secs(20));
        assert!(alive(agent_pid), "the agent never started");

        coordinator
            .kill()
            .expect("hard-kill the disposable coordinator");
        coordinator.wait().expect("reap the disposable coordinator");
        assert!(
            alive(holder),
            "the pipe holder died with its parent, so no EOF was withheld and \
             this test would pass without the reparenting check"
        );

        let deadline = Instant::now() + Duration::from_secs(20);
        while alive(agent_pid) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(50));
        }
        let settled = !alive(agent_pid);
        // SAFETY: cleanup for the failing case, a no-op for the passing one.
        unsafe {
            let _ = libc::kill(holder, libc::SIGKILL);
            let _ = libc::kill(agent_pid, libc::SIGKILL);
            let _ = libc::kill(-agent_pid, libc::SIGKILL);
        }
        let _ = std::fs::remove_dir_all(&scratch);
        assert!(
            settled,
            "the reaper waited for a pipe EOF that a surviving fork will never \
             deliver: on Darwin that is an agent group nothing settles"
        );
    }

    /// A **real** ambient-job failure refuses the write command.
    ///
    /// `crash_reconstruction`: "if the ambient job cannot be created or joined
    /// the write command refuses at startup with a diagnostic before any
    /// workspace effect (no degraded mode; deferred)". The suite's other
    /// ambient failure is the harness injection, and that fires *before* this
    /// step — so the branch that carries a real `join_ambient` error was
    /// unwitnessed, and deleting it (`let _ = windows_job::join_ambient();`)
    /// left `run` and `resume` dispatching with no ambient job while every
    /// test stayed green.
    ///
    /// The two failures are told apart by their wording, which is the point:
    /// an injected failure must not be able to stand in for the real one.
    #[cfg(windows)]
    #[test]
    fn a_real_ambient_join_failure_refuses_the_write_command() {
        let error = join_ambient_job_with(&mut NoHooks, || {
            Err("it could not be created (simulated OS failure)".to_owned())
        })
        .expect_err("a failed ambient join must refuse the write command");
        let message = error.to_string();
        assert!(
            message.starts_with(AMBIENT_REFUSAL_PREFIX),
            "the refusal must carry the diagnostic: {message}"
        );
        assert!(
            message.contains("simulated OS failure"),
            "the OS's own reason must survive into the refusal: {message}"
        );
        assert!(
            message.contains("No process was spawned"),
            "the refusal must say nothing was started: {message}"
        );
        assert!(
            !message.contains(AMBIENT_REFUSAL_SIMULATED),
            "a real failure was reported as the injected one: {message}"
        );
        assert!(
            matches!(error, TactusError::Refused { .. }),
            "a refusal, not an agent error: {error:?}"
        );

        // And a join that succeeds is not turned into a refusal.
        join_ambient_job_with(&mut NoHooks, || Ok(())).expect("a successful ambient join proceeds");
    }

    #[cfg(windows)]
    fn windows_descendant_command(ready: &std::path::Path, marker: &std::path::Path) -> Command {
        let mut command = Command::new(std::env::current_exe().expect("test executable"));
        command
            .args(["windows_delayed_marker_helper", "--ignored", "--nocapture"])
            .env("TACTUS_WINDOWS_DESCENDANT", "1")
            .env("TACTUS_READY", ready)
            .env("TACTUS_MARKER", marker)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    #[cfg(windows)]
    fn windows_tree_scratch(tag: &str) -> std::path::PathBuf {
        let scratch = std::env::temp_dir().join(format!(
            "tactus-windows-job-{tag}-{}-{}",
            std::process::id(),
            crate::ulid::ulid()
        ));
        std::fs::create_dir_all(&scratch).expect("create Windows job scratch directory");
        scratch
    }

    #[cfg(windows)]
    fn wait_for_marker(path: &std::path::Path, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while !path.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(path.exists(), "{} was not created", path.display());
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "subprocess helper"]
    fn windows_delayed_marker_helper() {
        if std::env::var_os("TACTUS_WINDOWS_DESCENDANT").is_none() {
            return;
        }
        let ready = std::env::var_os("TACTUS_READY").expect("ready path");
        let marker = std::env::var_os("TACTUS_MARKER").expect("marker path");
        std::fs::write(ready, b"ready").expect("announce descendant start");
        thread::sleep(Duration::from_secs(1));
        std::fs::write(marker, b"leaked").expect("write delayed marker");
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "subprocess helper"]
    #[allow(clippy::zombie_processes)]
    fn windows_direct_exit_parent_helper() {
        if std::env::var_os("TACTUS_WINDOWS_DIRECT_PARENT").is_none() {
            return;
        }
        let ready = std::path::PathBuf::from(std::env::var_os("TACTUS_READY").expect("ready path"));
        let marker =
            std::path::PathBuf::from(std::env::var_os("TACTUS_MARKER").expect("marker path"));
        windows_descendant_command(&ready, &marker)
            .spawn()
            .expect("spawn ordinary descendant");
        wait_for_marker(&ready, Duration::from_secs(10));
        // Returning successfully while the child is live models a CLI shim
        // whose real worker outlives it.
    }

    #[cfg(windows)]
    #[test]
    fn successful_direct_exit_kills_windows_descendants() {
        let scratch = windows_tree_scratch("direct-exit");
        let ready = scratch.join("ready");
        let marker = scratch.join("marker");
        let mut command = Command::new(std::env::current_exe().expect("test executable"));
        command
            .args([
                "windows_direct_exit_parent_helper",
                "--ignored",
                "--nocapture",
            ])
            .env("TACTUS_WINDOWS_DIRECT_PARENT", "1")
            .env("TACTUS_READY", &ready)
            .env("TACTUS_MARKER", &marker);

        let output = run_with_timeout(command, "", Duration::from_secs(20))
            .expect("supervise direct-exit tree");
        assert_eq!(output.code, Some(0), "supervised output: {output:?}");
        assert!(ready.exists(), "the descendant never began executing");
        thread::sleep(Duration::from_millis(1300));
        let leaked = marker.exists();
        let _ = std::fs::remove_dir_all(&scratch);
        assert!(
            !leaked,
            "a Windows descendant outlived its successful parent"
        );
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "subprocess helper"]
    fn windows_job_owner_helper() {
        if std::env::var_os("TACTUS_WINDOWS_JOB_OWNER").is_none() {
            return;
        }
        let ready = std::path::PathBuf::from(std::env::var_os("TACTUS_READY").expect("ready path"));
        let marker =
            std::path::PathBuf::from(std::env::var_os("TACTUS_MARKER").expect("marker path"));
        let command = windows_descendant_command(&ready, &marker);
        let _ = run_with_timeout(command, "", Duration::from_secs(30));
    }

    #[cfg(windows)]
    #[test]
    fn kill_on_close_cleans_windows_descendants_after_conductor_death() {
        let scratch = windows_tree_scratch("kill-on-close");
        let ready = scratch.join("ready");
        let marker = scratch.join("marker");
        let mut owner = Command::new(std::env::current_exe().expect("test executable"))
            .args(["windows_job_owner_helper", "--ignored", "--nocapture"])
            .env("TACTUS_WINDOWS_JOB_OWNER", "1")
            .env("TACTUS_READY", &ready)
            .env("TACTUS_MARKER", &marker)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn disposable job owner");
        wait_for_marker(&ready, Duration::from_secs(10));
        owner.kill().expect("hard-kill disposable job owner");
        owner.wait().expect("reap disposable job owner");

        thread::sleep(Duration::from_millis(1300));
        let leaked = marker.exists();
        let _ = std::fs::remove_dir_all(&scratch);
        assert!(
            !leaked,
            "kill-on-close did not terminate the owned descendant"
        );
    }

    /// `{pid} {creation_time}` for this process.
    ///
    /// A pid alone is not an identity — Windows reuses them — so a test that
    /// asks "is it gone" by pid could be answered by an unrelated process that
    /// inherited the number.
    #[cfg(windows)]
    fn windows_self_identity() -> String {
        let pid = std::process::id();
        let created = process_creation_time(pid).expect("this process has a creation time");
        format!("{pid} {created}")
    }

    #[cfg(windows)]
    fn read_windows_identity(path: &std::path::Path, timeout: Duration) -> (u32, u64) {
        let deadline = Instant::now() + timeout;
        loop {
            if let Ok(text) = std::fs::read_to_string(path) {
                let mut fields = text.split_whitespace();
                if let (Some(pid), Some(created)) = (fields.next(), fields.next()) {
                    if let (Ok(pid), Ok(created)) = (pid.parse(), created.parse()) {
                        return (pid, created);
                    }
                }
            }
            assert!(
                Instant::now() < deadline,
                "{} never carried a process identity",
                path.display()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// A grandchild that reports the moment it outlives the process Tactus
    /// waits on.
    ///
    /// It announces its own identity, then polls for the direct child's death
    /// and writes `ESCAPED` to the **inherited stderr** only after observing it
    /// gone three times 30 ms apart. `TerminateJobObject` ends every member of
    /// the job at once, so a contained grandchild cannot survive that 90 ms
    /// window; one whose parent alone was killed survives the whole drain grace
    /// and is captured. stderr rather than stdout because the output-limit
    /// fixture deliberately fills stdout past the point where the drain stops
    /// retaining what it reads.
    #[cfg(windows)]
    #[test]
    #[ignore = "subprocess helper"]
    fn windows_escape_watcher_helper() {
        use std::io::Write;

        if std::env::var_os("TACTUS_WINDOWS_WATCHER").is_none() {
            return;
        }
        let ready = std::env::var_os("TACTUS_READY").expect("ready path");
        let parent: u32 = std::env::var("TACTUS_PARENT_PID")
            .expect("parent pid")
            .parse()
            .expect("parent pid");
        let created: u64 = std::env::var("TACTUS_PARENT_CREATED")
            .expect("parent creation time")
            .parse()
            .expect("parent creation time");
        std::fs::write(ready, windows_self_identity()).expect("announce the watcher");
        let mut gone = 0_u8;
        for _ in 0..2000 {
            if process_alive(parent, created) {
                gone = 0;
            } else {
                gone += 1;
            }
            if gone >= 3 {
                eprint!("ESCAPED");
                let _ = std::io::stderr().flush();
                // Long enough that a bounded wait for termination cannot be
                // satisfied by this process simply finishing.
                thread::sleep(Duration::from_secs(90));
                return;
            }
            thread::sleep(Duration::from_millis(30));
        }
    }

    /// The direct child of the two Windows escape fixtures: start the watcher,
    /// wait for it, then either fill stdout or wait to be timed out.
    #[cfg(windows)]
    #[test]
    #[ignore = "subprocess helper"]
    #[allow(clippy::zombie_processes)]
    fn windows_escape_parent_helper() {
        use std::io::Write;

        if std::env::var_os("TACTUS_WINDOWS_ESCAPE_PARENT").is_none() {
            return;
        }
        let ready = std::path::PathBuf::from(std::env::var_os("TACTUS_READY").expect("ready path"));
        let pid = std::process::id();
        let created = process_creation_time(pid).expect("own creation time");
        Command::new(std::env::current_exe().expect("test executable"))
            .args(["windows_escape_watcher_helper", "--ignored", "--nocapture"])
            .env("TACTUS_WINDOWS_WATCHER", "1")
            .env("TACTUS_READY", &ready)
            .env("TACTUS_PARENT_PID", pid.to_string())
            .env("TACTUS_PARENT_CREATED", created.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn the escape watcher");
        wait_for_marker(&ready, Duration::from_secs(20));
        if std::env::var_os("TACTUS_MODE").is_some_and(|mode| mode == "flood") {
            let block = vec![b'x'; 8192];
            let mut out = std::io::stdout();
            while out.write_all(&block).is_ok() && out.flush().is_ok() {}
            return;
        }
        thread::sleep(Duration::from_secs(60));
    }

    /// Whether `pid` is *still* running after a bounded wait.
    ///
    /// The supervisor drops its `ProcessTree` before it returns, so by the time
    /// a caller can look, termination is under way by one route or another and
    /// a process in the middle of its exit path can still answer "alive" for a
    /// few milliseconds. The bound absorbs that and nothing else: an escaped
    /// grandchild in these fixtures outlives it by ninety seconds.
    ///
    /// This is the secondary witness. The primary one is the `ESCAPED` sentinel
    /// in the captured transcript, which is exact and unbounded — a contained
    /// grandchild never writes it at all.
    #[cfg(windows)]
    fn still_running_after(pid: u32, created: u64, bound: Duration) -> bool {
        let deadline = Instant::now() + bound;
        while process_alive(pid, created) {
            if Instant::now() >= deadline {
                return true;
            }
            thread::sleep(Duration::from_millis(20));
        }
        false
    }

    #[cfg(windows)]
    fn windows_escape_command(ready: &std::path::Path, mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().expect("test executable"));
        command
            .args(["windows_escape_parent_helper", "--ignored", "--nocapture"])
            .env("TACTUS_WINDOWS_ESCAPE_PARENT", "1")
            .env("TACTUS_READY", ready)
            .env("TACTUS_MODE", mode);
        command
    }

    /// `kill_tree` settles the whole job **before it returns**, and the job it
    /// settles is this invocation's own.
    ///
    /// Both properties are invisible through the funnel, and for the same
    /// reason: `ProcessTree` is dropped inside the supervisor, and
    /// `KILL_ON_JOB_CLOSE` then terminates every descendant with no help from
    /// any code under test. So both a cleanup that never terminated the job and
    /// a cleanup that terminated only the direct child by pid look, from
    /// outside, exactly like this one. Here the tree is still alive at the
    /// assertion — the handle is open and the fail-safe has not fired — so
    /// whatever settled the grandchild was `kill_tree` itself.
    ///
    /// The private job's separate identity is the other half: DESIGN.md:402's
    /// "private per-invocation jobs scope timeouts" is a claim about *which*
    /// job, and the coordinator is a member of the ambient one. A tree that
    /// carried the ambient handle instead would answer this query the other
    /// way — and would terminate the coordinator on the next timeout.
    #[cfg(windows)]
    #[test]
    fn kill_tree_observes_the_windows_job_empty_before_it_returns() {
        let scratch = windows_tree_scratch("kill-tree");
        let ready = scratch.join("ready");
        let mut command = windows_escape_command(&ready, "sleep");
        command.stdin(Stdio::null());
        let mut tree = ProcessTree::spawn(&mut command, &mut NoHooks).expect("spawn a tree");
        let (pid, created) = read_windows_identity(&ready, Duration::from_secs(30));
        assert!(process_alive(pid, created), "the grandchild never ran");
        assert_eq!(
            tree.job.contains(tree.child.id()),
            Some(true),
            "the direct child is not in the job that owns its tree"
        );
        // Read the answer before acting on it. If the coordinator really is a
        // member, *closing* this handle terminates this process — so a plain
        // `assert_eq!` would unwind, drop the job, and take the report with it:
        // the run ends with `running 1 test` and no result line, which reads
        // like infrastructure rather than like this assertion. Leak the handle
        // instead, and fail in words.
        if tree.job.contains(std::process::id()) != Some(false) {
            std::mem::forget(tree);
            let _ = std::fs::remove_dir_all(&scratch);
            panic!(
                "the coordinator is a member of the per-invocation job: a timeout \
                 on one invocation would terminate the coordinator and every other \
                 invocation with it"
            );
        }

        kill_tree(&mut tree).expect("settle the tree");
        // Bounded rather than instantaneous: a job the kernel has already
        // emptied can still be running the last of its exit paths when this
        // line does. What the bound cannot absorb is a member that was never
        // terminated — the fixture's grandchild outlives it by a minute either
        // way. `tree` is still alive throughout, so KILL_ON_JOB_CLOSE has not
        // fired and cannot be what settled anything.
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut escaped = process_alive(pid, created);
        while escaped && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
            escaped = process_alive(pid, created);
        }
        let in_job = tree.job.contains(pid);
        drop(tree);
        let _ = std::fs::remove_dir_all(&scratch);
        assert!(
            !escaped,
            "kill_tree returned while a member of the job was still running \
             (grandchild in this job: {in_job:?}): the job was never observed empty"
        );
    }

    /// The Windows timeout path, watched from the grandchild.
    ///
    /// `timeout_kills_the_process_tree_quickly` reaches this branch on Windows
    /// but only ever asks about the direct child; the test that looks for the
    /// grandchild is `#[cfg(unix)]`. This is its Windows sibling.
    #[cfg(windows)]
    #[test]
    fn timeout_kills_a_windows_grandchild_before_it_can_escape() {
        let scratch = windows_tree_scratch("timeout-escape");
        let ready = scratch.join("ready");
        let output = run_with_timeout(
            windows_escape_command(&ready, "sleep"),
            "",
            Duration::from_secs(3),
        )
        .expect("supervise the tree");
        let (pid, created) = read_windows_identity(&ready, Duration::from_secs(30));
        let escaped = still_running_after(pid, created, Duration::from_secs(3));
        let _ = std::fs::remove_dir_all(&scratch);
        assert!(output.timed_out, "{output:?}");
        assert!(
            !output.stderr.contains("ESCAPED"),
            "a Windows grandchild outlived its timed-out tree: {}",
            output.stderr
        );
        assert!(
            !escaped,
            "the grandchild was still running when the supervisor returned"
        );
    }

    /// And the output-limit path settles the same tree the same way.
    ///
    /// `invariants_preserved[0]` is "process supervision, timeout, output
    /// capture … unchanged (host contract: ordinary descendants only)": the
    /// allowance branch is not a lesser kind of termination. Its fixture fills
    /// **stdout**, so the escape sentinel goes to stderr, which keeps its own
    /// allowance and therefore keeps retaining.
    #[cfg(windows)]
    #[test]
    fn the_output_limit_path_settles_a_windows_grandchild_too() {
        let scratch = windows_tree_scratch("limit-escape");
        let ready = scratch.join("ready");
        let output = run_with_timeout_and_limit(
            windows_escape_command(&ready, "flood"),
            b"",
            Duration::from_secs(60),
            64 * 1024,
            &mut NoHooks,
        )
        .expect("supervise the tree");
        let (pid, created) = read_windows_identity(&ready, Duration::from_secs(30));
        let escaped = still_running_after(pid, created, Duration::from_secs(3));
        let _ = std::fs::remove_dir_all(&scratch);
        assert!(output.output_limited, "{output:?}");
        assert!(
            !output.stderr.contains("ESCAPED"),
            "a Windows grandchild outlived an output-limited tree: {}",
            output.stderr
        );
        assert!(
            !escaped,
            "the grandchild was still running when the supervisor returned"
        );
    }

    /// Every Windows containment point, measured against the operation it is
    /// named for rather than against the other points.
    ///
    /// `containment_sub_effects` says "ST-07 evidence executes each point **on
    /// its platform**", and the three per-spawn Windows points make claims the
    /// suite could only check by name and relative order: `CreatedSuspended`
    /// says the child exists and is not yet in the private job,
    /// `PrivateJobAssigned` says it is in the private job and *still
    /// suspended*, `Resumed` says it is not. Each could be moved to the wrong
    /// side of its own operation and stay green.
    ///
    /// The oracles are the kernel's, following `child_leads_its_own_group`:
    /// `SuspendThread`'s returned count for suspension, `IsProcessInJob` for
    /// membership — the membership question asked of a handle captured through
    /// the assignment seam, so a hook that fires before the assignment has no
    /// handle to ask about. The child's first instruction is a third,
    /// end-to-end witness: a suspended process cannot write it in any amount of
    /// time, so the two pre-resume points sample it after a grace rather than
    /// instantaneously.
    ///
    /// The expected table is transcribed from that sentence, not read back.
    #[cfg(windows)]
    #[test]
    fn every_windows_containment_point_is_measured_against_its_own_operation() {
        use std::cell::RefCell;
        use std::rc::Rc;
        use windows_sys::Win32::Foundation::HANDLE;

        #[derive(Debug, PartialEq, Eq)]
        struct Row {
            point: SubEffectPoint,
            suspended: bool,
            assignment_made: bool,
            in_private_job: Option<bool>,
            /// `None` at `Resumed`: after the resume the child is free to run,
            /// so neither answer would mean anything.
            first_instruction_ran: Option<bool>,
        }

        struct Shared {
            pid: Option<u32>,
            job: Option<HANDLE>,
            first_instruction: std::path::PathBuf,
            rows: Vec<Row>,
        }

        struct Observer(Rc<RefCell<Shared>>);

        impl SpawnHooks for Observer {
            fn child_created(&mut self, pid: u32) {
                self.0.borrow_mut().pid = Some(pid);
            }

            fn point(&mut self, point: SubEffectPoint) -> Injection {
                if point != SubEffectPoint::Resumed {
                    // Turn absence-at-an-instant into an observation: a running
                    // child writes its first instruction in milliseconds.
                    thread::sleep(Duration::from_millis(250));
                }
                let mut shared = self.0.borrow_mut();
                let pid = shared.pid.expect("the child exists at every point");
                let job = shared.job;
                let suspended = windows_job::primary_thread_suspend_count(pid)
                    .expect("read the child's suspend count")
                    > 0;
                let first_instruction_ran = if point == SubEffectPoint::Resumed {
                    None
                } else {
                    Some(shared.first_instruction.exists())
                };
                let row = Row {
                    point,
                    suspended,
                    assignment_made: job.is_some(),
                    in_private_job: job.and_then(|job| windows_job::job_contains(job, pid)),
                    first_instruction_ran,
                };
                shared.rows.push(row);
                Injection::Proceed
            }
        }

        let scratch = windows_tree_scratch("point-coordinates");
        let ready = scratch.join("ready");
        let marker = scratch.join("marker");
        let shared = Rc::new(RefCell::new(Shared {
            pid: None,
            job: None,
            first_instruction: ready.clone(),
            rows: Vec::new(),
        }));
        let mut command = windows_descendant_command(&ready, &marker);
        let mut hooks = Observer(Rc::clone(&shared));
        let assign_shared = Rc::clone(&shared);
        let (mut child, job) = windows_job::spawn_suspended_in_job_with(
            &mut command,
            &mut hooks,
            move |job, process| {
                assign_shared.borrow_mut().job = Some(job);
                windows_job::real_assign_to_job(job, process)
            },
            windows_job::resume_only_thread,
        )
        .expect("spawn a suspended child");

        // The positive control: the absences above were suspension, not a
        // helper that never runs.
        wait_for_marker(&ready, Duration::from_secs(20));
        let _ = job.terminate_and_wait();
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&scratch);

        let observed = &shared.borrow().rows;
        let expected = vec![
            Row {
                point: SubEffectPoint::CreatedSuspended,
                suspended: true,
                assignment_made: false,
                in_private_job: None,
                first_instruction_ran: Some(false),
            },
            Row {
                point: SubEffectPoint::PrivateJobAssigned,
                suspended: true,
                assignment_made: true,
                in_private_job: Some(true),
                first_instruction_ran: Some(false),
            },
            Row {
                point: SubEffectPoint::Resumed,
                suspended: false,
                assignment_made: true,
                in_private_job: Some(true),
                first_instruction_ran: None,
            },
        ];
        assert_eq!(
            *observed, expected,
            "a containment point no longer sits at the coordinate it names"
        );
    }

    /// The two spawn steps that can fail after the child exists leave nothing
    /// behind.
    ///
    /// R22: "created as an ambient-job member, so a coordinator death at any
    /// spawn sub-step **incl. the create-suspended prefix** terminates it".
    /// Neither `AssignProcessToJobObject` nor `ResumeThread` fails on a working
    /// machine, so both recovery branches — terminate the private job, kill the
    /// child, wait for it — were unreachable, and either could have returned
    /// the error while leaving a suspended stub that nothing owns.
    #[cfg(windows)]
    #[test]
    fn a_windows_spawn_that_fails_after_creation_leaves_no_suspended_stub() {
        use std::cell::RefCell;
        use std::rc::Rc;

        struct Capture(Rc<RefCell<Option<(u32, u64)>>>);

        impl SpawnHooks for Capture {
            fn point(&mut self, _point: SubEffectPoint) -> Injection {
                Injection::Proceed
            }

            fn child_created(&mut self, pid: u32) {
                let created = process_creation_time(pid).expect("the child has a creation time");
                *self.0.borrow_mut() = Some((pid, created));
            }
        }

        for (step, assign, resume) in [
            (
                "private-job assignment",
                None,
                None::<fn(u32) -> std::io::Result<()>>,
            ),
            (
                "resume",
                Some(windows_job::real_assign_to_job as fn(_, _) -> i32),
                Some(|_| Err(std::io::Error::other("simulated resume failure"))),
            ),
        ] {
            let scratch = windows_tree_scratch("spawn-failure");
            let ready = scratch.join("ready");
            let marker = scratch.join("marker");
            let seen = Rc::new(RefCell::new(None));
            let mut hooks = Capture(Rc::clone(&seen));
            let mut command = windows_descendant_command(&ready, &marker);
            let error = windows_job::spawn_suspended_in_job_with(
                &mut command,
                &mut hooks,
                move |job, process| assign.map_or(0, |assign| assign(job, process)),
                move |pid| resume.map_or_else(|| windows_job::resume_only_thread(pid), |r| r(pid)),
            )
            .err()
            .unwrap_or_else(|| panic!("a failed {step} must be a spawn failure"));
            let (pid, created) = seen
                .borrow()
                .unwrap_or_else(|| panic!("the child was created before the {step}"));
            let alive = process_alive(pid, created);
            let ran = ready.exists();
            let _ = std::fs::remove_dir_all(&scratch);
            assert!(
                !alive,
                "a suspended stub outlived the failed {step} ({error}): pid {pid} is still running"
            );
            assert!(
                !ran,
                "the child executed although the {step} it was waiting behind failed"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn successful_direct_exit_still_kills_detached_group_members() {
        let marker = std::env::temp_dir().join(format!(
            "tactus-proc-detached-{}-{}.marker",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&marker);
        let mut command = shell(
            "(sleep 1; printf leaked > \"$TACTUS_MARKER\") \
             </dev/null >/dev/null 2>&1 & exit 0",
        );
        command.env("TACTUS_MARKER", &marker);
        let output = run_with_timeout(command, "", Duration::from_secs(10)).expect("spawn shell");
        assert_eq!(output.code, Some(0));

        thread::sleep(Duration::from_millis(1300));
        let leaked = marker.exists();
        let _ = std::fs::remove_file(&marker);
        assert!(
            !leaked,
            "a detached descendant outlived the successful command"
        );
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "subprocess helper"]
    fn terminal_progress_worker_helper() {
        if std::env::var_os("TACTUS_SIGNAL_WORKER").is_none() {
            return;
        }
        let ready = std::env::var_os("TACTUS_READY").expect("ready path");
        let marker = std::env::var_os("TACTUS_MARKER").expect("marker path");
        let finish = std::env::var_os("TACTUS_FINISH").expect("finish path");
        let pid = unsafe { libc::getpid() };
        let pgid = unsafe { libc::getpgrp() };
        std::fs::write(ready, format!("{pid} {pgid} {pid} {pgid}")).expect("worker ready");
        let mut progress = 0_u64;
        while !std::path::Path::new(&finish).exists() {
            progress += 1;
            std::fs::write(&marker, progress.to_string()).expect("worker progress");
            thread::sleep(Duration::from_millis(50));
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_stopped_child_is_not_mistaken_for_an_exited_child() {
        let scratch = std::env::temp_dir().join(format!(
            "tactus-stopped-child-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&scratch).expect("scratch dir");
        let ready = scratch.join("ready");
        let marker = scratch.join("marker");
        let finish = scratch.join("finish");
        let mut child = Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "terminal_progress_worker_helper",
                "--ignored",
                "--nocapture",
            ])
            .env("TACTUS_SIGNAL_WORKER", "1")
            .env("TACTUS_READY", &ready)
            .env("TACTUS_MARKER", &marker)
            .env("TACTUS_FINISH", &finish)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn stopped-child helper");
        let pid = i32::try_from(child.id()).expect("child pid");
        let ready_deadline = Instant::now() + Duration::from_secs(5);
        while !ready.exists() && Instant::now() < ready_deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(ready.exists(), "stopped-child helper never became ready");
        assert_eq!(unsafe { libc::kill(pid, libc::SIGSTOP) }, 0);

        let stop_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe {
                    libc::waitid(
                        libc::P_PID,
                        pid as libc::id_t,
                        &mut info,
                        libc::WSTOPPED | libc::WNOHANG | libc::WNOWAIT,
                    )
                },
                0
            );
            if unsafe { info.si_pid() } == pid {
                break;
            }
            assert!(Instant::now() < stop_deadline, "child never stopped");
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !child_exited_unreaped(&child).expect("probe stopped child"),
            "a non-terminal child transition was mistaken for process exit"
        );

        let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(scratch);
    }

    /// Subprocess entry point for the Unix signal-supervision tests below.
    /// Ignored in ordinary test discovery; the parent test invokes only this
    /// case in a fresh process because the expected outcome is SIGINT.
    #[cfg(unix)]
    #[test]
    #[ignore = "subprocess helper"]
    fn terminal_interrupt_helper() {
        if std::env::var_os("TACTUS_SIGNAL_HELPER").is_none() {
            return;
        }
        // SIGQUIT normally requests a core dump. Disable it in this disposable
        // helper so the regression observes supervision semantics without
        // invoking a host crash reporter (notably ReportCrash on macOS).
        let no_core = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: this changes only the current disposable helper before it
        // launches either the signal monitor or the supervised command.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) }, 0);
        let _cleanup_lock = std::env::var_os("TACTUS_CLEANUP_PUBLIC").map(|public| {
            let public = std::path::PathBuf::from(public);
            std::fs::create_dir_all(&public).expect("cleanup-lock run directory");
            crate::rundir::RunLock::acquire(&public).expect("cleanup-lock helper takes run")
        });
        let _cleanup_scope = _cleanup_lock
            .as_ref()
            .map(crate::rundir::RunLock::enter_cleanup_scope);
        if let Some(blocked_signal) = std::env::var_os("TACTUS_BLOCK_SIGNAL") {
            // SAFETY: this disposable process deliberately models an embedding
            // host that blocked the selected signal before Tactus initialized
            // supervision.
            let blocked_signal = blocked_signal
                .to_string_lossy()
                .parse::<libc::c_int>()
                .expect("numeric blocked signal");
            unsafe {
                let mut blocked: libc::sigset_t = std::mem::zeroed();
                assert_eq!(libc::sigemptyset(&mut blocked), 0);
                assert_eq!(libc::sigaddset(&mut blocked, blocked_signal), 0);
                assert_eq!(
                    libc::sigprocmask(libc::SIG_BLOCK, &blocked, std::ptr::null_mut()),
                    0
                );
            }
        }
        let custom_handler = std::env::var_os("TACTUS_CUSTOM_SIGNAL_HANDLER").is_some();
        if custom_handler {
            CUSTOM_SIGNAL_SEEN.store(false, std::sync::atomic::Ordering::SeqCst);
            assert_ne!(
                unsafe {
                    libc::signal(
                        libc::SIGTERM,
                        record_custom_signal as *const () as libc::sighandler_t,
                    )
                },
                libc::SIG_ERR
            );
        }
        let custom_job_control = std::env::var_os("TACTUS_CUSTOM_JOB_CONTROL_HANDLER").is_some();
        if custom_job_control {
            CUSTOM_JOB_CONTROL_SEEN.store(false, std::sync::atomic::Ordering::SeqCst);
            CUSTOM_PARENT_PID.store(
                unsafe { libc::getpid() },
                std::sync::atomic::Ordering::SeqCst,
            );
            assert_ne!(
                unsafe {
                    libc::signal(
                        libc::SIGTSTP,
                        record_custom_job_control as *const () as libc::sighandler_t,
                    )
                },
                libc::SIG_ERR
            );
        }
        if std::env::var_os("TACTUS_CUSTOM_CONTINUE_HANDLER").is_some() {
            assert_ne!(
                unsafe {
                    libc::signal(
                        libc::SIGCONT,
                        record_custom_continue as *const () as libc::sighandler_t,
                    )
                },
                libc::SIG_ERR
            );
        }
        let custom_aux_signal = std::env::var_os("TACTUS_CUSTOM_AUX_SIGNAL_HANDLER").is_some();
        if custom_aux_signal {
            CUSTOM_AUX_SIGNAL_SEEN.store(false, std::sync::atomic::Ordering::SeqCst);
            CUSTOM_PARENT_PID.store(
                unsafe { libc::getpid() },
                std::sync::atomic::Ordering::SeqCst,
            );
            assert_ne!(
                unsafe {
                    libc::signal(
                        libc::SIGUSR1,
                        record_custom_aux_signal as *const () as libc::sighandler_t,
                    )
                },
                libc::SIG_ERR
            );
        }
        let progress_loop = std::env::var_os("TACTUS_SIGNAL_PROGRESS_LOOP").is_some();
        let mut command = if progress_loop {
            let mut command = Command::new(std::env::current_exe().expect("test executable"));
            command.args([
                "terminal_progress_worker_helper",
                "--ignored",
                "--nocapture",
            ]);
            command.env("TACTUS_SIGNAL_WORKER", "1");
            command
        } else {
            let script = "(sleep 1; printf leaked > \"$TACTUS_MARKER\") & worker=$!; \
             shell_pgid=$(ps -o pgid= -p $$ | tr -d ' '); \
             worker_pgid=$(ps -o pgid= -p $worker | tr -d ' '); \
             printf '%s %s %s %s' $$ $shell_pgid $worker $worker_pgid > \"$TACTUS_READY\"; \
             wait";
            shell(script)
        };
        command.env(
            "TACTUS_READY",
            std::env::var_os("TACTUS_READY").expect("ready path"),
        );
        command.env(
            "TACTUS_MARKER",
            std::env::var_os("TACTUS_MARKER").expect("marker path"),
        );
        if let Some(finish) = std::env::var_os("TACTUS_FINISH") {
            command.env("TACTUS_FINISH", finish);
        }
        let result = run_with_timeout(command, "", Duration::from_secs(30));
        if std::env::var_os("TACTUS_EXPECT_JOB_CONTROL_REFUSAL").is_some() {
            let error = result.expect_err("host-owned SIGCONT must refuse default stop proxying");
            assert!(
                error
                    .to_string()
                    .contains("cannot safely proxy default Unix job-control stops"),
                "unexpected policy error: {error}"
            );
            return;
        }
        let output = result.expect("signal helper command");
        if std::env::var_os("TACTUS_SIGNAL_HELPER_EXPECT_RETURN").is_some() {
            assert_eq!(output.code, Some(0), "supervised output: {output:?}");
            if custom_handler {
                assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
                assert!(
                    CUSTOM_SIGNAL_SEEN.load(std::sync::atomic::Ordering::SeqCst),
                    "Tactus replaced the embedding host's custom SIGTERM handler"
                );
            }
            if custom_job_control {
                assert!(
                    CUSTOM_JOB_CONTROL_SEEN.load(std::sync::atomic::Ordering::SeqCst),
                    "Tactus replaced the embedding host's custom SIGTSTP handler"
                );
            }
            if custom_aux_signal {
                assert!(
                    CUSTOM_AUX_SIGNAL_SEEN.load(std::sync::atomic::Ordering::SeqCst),
                    "the embedding host did not receive its own SIGUSR1"
                );
            }
            return;
        }
        panic!("the helper should terminate with the forwarded signal");
    }

    #[cfg(unix)]
    static CUSTOM_SIGNAL_SEEN: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    #[cfg(unix)]
    static CUSTOM_JOB_CONTROL_SEEN: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    #[cfg(unix)]
    static CUSTOM_AUX_SIGNAL_SEEN: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    #[cfg(unix)]
    static CUSTOM_PARENT_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

    #[cfg(unix)]
    extern "C" fn record_custom_signal(_: libc::c_int) {
        CUSTOM_SIGNAL_SEEN.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(unix)]
    extern "C" fn record_custom_job_control(_: libc::c_int) {
        let parent = CUSTOM_PARENT_PID.load(std::sync::atomic::Ordering::SeqCst);
        if unsafe { libc::getpid() } == parent {
            CUSTOM_JOB_CONTROL_SEEN.store(true, std::sync::atomic::Ordering::SeqCst);
        } else if parent > 0 {
            // A fork-copied host callback executing in the private guard is a
            // test failure: terminate the disposable parent immediately so the
            // outer test observes it rather than relying on private atomics.
            let _ = unsafe { libc::kill(parent, libc::SIGKILL) };
        }
    }

    #[cfg(unix)]
    extern "C" fn record_custom_continue(_: libc::c_int) {}

    #[cfg(unix)]
    extern "C" fn record_custom_aux_signal(_: libc::c_int) {
        let parent = CUSTOM_PARENT_PID.load(std::sync::atomic::Ordering::SeqCst);
        if unsafe { libc::getpid() } == parent {
            CUSTOM_AUX_SIGNAL_SEEN.store(true, std::sync::atomic::Ordering::SeqCst);
        } else if parent > 0 {
            // Any forked helper that retained this callback turns a harmless
            // auxiliary signal into an observable failure in the disposable
            // parent instead of mutating only its private atomic copy.
            let _ = unsafe { libc::kill(parent, libc::SIGKILL) };
        }
    }

    #[cfg(unix)]
    struct SignalHelper {
        child: Child,
        scratch: std::path::PathBuf,
        marker: std::path::PathBuf,
        finish: std::path::PathBuf,
        diagnostic: std::path::PathBuf,
        reaper_pid_path: std::path::PathBuf,
        supervised_pgid: Option<i32>,
        active: bool,
    }

    #[cfg(unix)]
    impl SignalHelper {
        fn pid(&self) -> i32 {
            i32::try_from(self.child.id()).expect("helper pid")
        }

        fn complete(&mut self) {
            self.active = false;
            let _ = std::fs::remove_dir_all(&self.scratch);
        }

        fn diagnostic(&self) -> String {
            std::fs::read_to_string(&self.diagnostic)
                .unwrap_or_else(|error| format!("<could not read helper diagnostic: {error}>"))
        }
    }

    #[cfg(unix)]
    impl Drop for SignalHelper {
        fn drop(&mut self) {
            if !self.active {
                return;
            }
            // A failed assertion must never strand either the helper's guard
            // group or its separately isolated agent group (the macOS runner
            // would otherwise wait forever for a suspended descendant).
            if let Some(pgid) = self.supervised_pgid {
                let _ = unsafe { libc::kill(-pgid, libc::SIGKILL) };
            }
            let _ = unsafe { libc::kill(-self.pid(), libc::SIGKILL) };
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = std::fs::remove_dir_all(&self.scratch);
        }
    }

    #[cfg(unix)]
    fn spawn_signal_helper(tag: &str, expect_return: bool, ignore_sighup: bool) -> SignalHelper {
        use std::os::unix::process::CommandExt;

        let scratch = std::env::temp_dir().join(format!(
            "tactus-proc-{tag}-{}-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed"),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).expect("scratch dir");
        let ready = scratch.join("ready");
        let marker = scratch.join("leaked");
        let finish = scratch.join("finish");
        let diagnostic = scratch.join("helper.log");
        let reaper_pid_path = scratch.join("reaper.pid");
        let diagnostic_stdout = std::fs::File::create(&diagnostic).expect("helper diagnostic");
        let diagnostic_stderr = diagnostic_stdout
            .try_clone()
            .expect("clone helper diagnostic");

        let mut helper = Command::new(std::env::current_exe().expect("test executable"));
        helper
            .args(["terminal_interrupt_helper", "--ignored", "--nocapture"])
            .env("TACTUS_SIGNAL_HELPER", "1")
            .env("TACTUS_READY", &ready)
            .env("TACTUS_MARKER", &marker)
            .env("TACTUS_FINISH", &finish)
            .env("TACTUS_TEST_REAPER_PID_PATH", &reaper_pid_path)
            // Keep a broken child-group setup inside the disposable helper's
            // group. A regression must fail the test, never suspend the test
            // runner that is responsible for reporting and cleaning it up.
            .process_group(0)
            .stdout(Stdio::from(diagnostic_stdout))
            .stderr(Stdio::from(diagnostic_stderr));
        if expect_return {
            helper.env("TACTUS_SIGNAL_HELPER_EXPECT_RETURN", "1");
        }
        if tag.starts_with("job-control") || tag == "crash-lease" {
            helper.env("TACTUS_SIGNAL_PROGRESS_LOOP", "1");
        }
        if ignore_sighup {
            // SAFETY: `pre_exec` performs only the async-signal-safe `signal`
            // call. SIG_IGN is deliberately inherited across exec by POSIX.
            unsafe {
                helper.pre_exec(|| {
                    if libc::signal(libc::SIGHUP, libc::SIG_IGN) == libc::SIG_ERR {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(())
                    }
                });
            }
        }
        if matches!(tag, "custom-handler" | "job-control-custom") {
            helper.env("TACTUS_CUSTOM_SIGNAL_HANDLER", "1");
        }
        if tag == "custom-job-control" {
            helper.env("TACTUS_CUSTOM_JOB_CONTROL_HANDLER", "1");
        }
        if tag == "custom-aux-signal" {
            helper.env("TACTUS_CUSTOM_AUX_SIGNAL_HANDLER", "1");
        }
        let blocked_signal = if tag == "job-control-cont-blocked" {
            Some(libc::SIGCONT)
        } else if tag.contains("blocked") {
            Some(libc::SIGTERM)
        } else {
            None
        };
        if let Some(blocked_signal) = blocked_signal {
            helper.env("TACTUS_BLOCK_SIGNAL", blocked_signal.to_string());
            // Block before exec so every thread subsequently created by the
            // Rust test harness inherits the host policy. Blocking only in the
            // selected test thread would leave another harness thread able to
            // receive the process-directed signal.
            unsafe {
                helper.pre_exec(move || {
                    let mut blocked: libc::sigset_t = std::mem::zeroed();
                    if libc::sigemptyset(&mut blocked) != 0
                        || libc::sigaddset(&mut blocked, blocked_signal) != 0
                        || libc::sigprocmask(libc::SIG_BLOCK, &blocked, std::ptr::null_mut()) != 0
                    {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(())
                    }
                });
            }
        }
        if tag == "crash-lease" {
            helper
                .env("TACTUS_CLEANUP_PUBLIC", scratch.join("run"))
                .env("TACTUS_TEST_CLEANUP_DELAY_MS", "700");
        }
        let child = helper.spawn().expect("spawn signal helper");
        let mut helper = SignalHelper {
            child,
            scratch,
            marker,
            finish,
            diagnostic,
            reaper_pid_path,
            supervised_pgid: None,
            active: true,
        };

        let ready_deadline = Instant::now() + Duration::from_secs(10);
        let mut last_identities = String::new();
        let identities = loop {
            if let Some(status) = helper.child.try_wait().expect("poll helper") {
                panic!("signal helper exited before its child was ready: {status}");
            }
            if let Ok(current) = std::fs::read_to_string(&ready) {
                if current.split_whitespace().count() == 4 {
                    break current;
                }
                last_identities = current;
            }
            if Instant::now() >= ready_deadline {
                panic!(
                    "signal helper never published complete child identities; last payload: \
                     {last_identities:?}"
                );
            }
            thread::sleep(Duration::from_millis(20));
        };
        let fields = identities.split_whitespace().collect::<Vec<_>>();
        assert_eq!(fields.len(), 4, "signal helper identities: {identities}");
        assert_eq!(
            fields[0], fields[1],
            "the supervised shell is not its process-group leader: {identities}"
        );
        assert_eq!(
            fields[1], fields[3],
            "the test descendant escaped the supervised group: {identities}"
        );
        helper.supervised_pgid = Some(fields[1].parse().expect("supervised process-group id"));
        helper
    }

    #[cfg(unix)]
    fn wait_for_exit(child: &mut Child, timeout: Duration) -> Option<std::process::ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = child.try_wait().expect("poll signal helper") {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    #[cfg(unix)]
    fn wait_for_stop(pid: i32, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let mut status = 0;
            // SAFETY: callers pass an unreaped child pid; WNOHANG avoids an
            // unbounded wait and WUNTRACED reports the guard's SIGSTOP.
            let waited =
                unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG | libc::WUNTRACED) };
            assert!(waited >= 0, "waitpid: {}", std::io::Error::last_os_error());
            if waited == pid && libc::WIFSTOPPED(status) {
                return true;
            }
            thread::sleep(Duration::from_millis(20));
        }
        false
    }

    /// Wait until the supervised worker has written its marker at least once.
    ///
    /// **Why this exists.** Every stop test sends its signal to the whole
    /// process group immediately after spawn, and then reads the marker. If the
    /// worker has not yet created it, the group is already stopped, the file can
    /// never appear, and the first read fails `ENOENT` — for ever, not flakily.
    /// `wait_for_stop` cannot cover this: it observes the *helper*, and says
    /// nothing about whether the worker ever ran.
    ///
    /// Measured on PR6: `agent::proc::tests::uncatchable_sigstop_covers_the_isolated_tree`
    /// failed on `macos-latest` with *"progress before signal 17: No such file
    /// or directory"* on a tree whose suite had grown to 1243 macOS tests. The
    /// race is PR4-era and pre-existing; it surfaced when the runner got busier.
    /// A test that passes because a spawn usually wins a race is not a test.
    #[cfg(unix)]
    fn wait_for_first_progress(marker: &std::path::Path, context: &str) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if marker.exists() {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("the supervised worker never recorded progress before {context}");
    }

    #[cfg(unix)]
    fn settled_progress_after_stop(marker: &std::path::Path, context: &str) -> String {
        // A process-group snapshot can report every member stopped while a
        // write already accepted by the kernel is still becoming visible on
        // disk (observed on macOS). Require more than two 50 ms worker periods
        // with no change before measuring the sustained stop. A genuinely
        // running worker keeps incrementing and either fails here or in the
        // longer assertion interval at the call site.
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut previous = std::fs::read_to_string(marker)
            .unwrap_or_else(|error| panic!("progress before {context}: {error}"));
        loop {
            thread::sleep(Duration::from_millis(125));
            let current = std::fs::read_to_string(marker)
                .unwrap_or_else(|error| panic!("progress while settling {context}: {error}"));
            if current == previous {
                return current;
            }
            assert!(
                Instant::now() < deadline,
                "the isolated agent never became quiescent during {context}: {previous} -> {current}"
            );
            previous = current;
        }
    }

    #[cfg(unix)]
    fn assert_termination_kills_the_isolated_tree(signal: libc::c_int, tag: &str) {
        let mut helper = spawn_signal_helper(tag, false, false);
        let pid = helper.pid();
        // SAFETY: the helper owns a dedicated process group. Terminal signals
        // target foreground groups, which also exercises the external guard.
        assert_eq!(unsafe { libc::kill(-pid, signal) }, 0);
        if wait_for_exit(&mut helper.child, Duration::from_secs(10)).is_none() {
            panic!("signalled supervisor did not terminate promptly");
        }

        thread::sleep(Duration::from_millis(1300));
        let leaked = helper.marker.exists();
        helper.complete();
        assert!(
            !leaked,
            "signal {signal} terminated Tactus but left its isolated agent tree alive"
        );
    }

    #[cfg(unix)]
    #[test]
    fn terminal_interrupt_kills_the_isolated_tree() {
        assert_termination_kills_the_isolated_tree(libc::SIGINT, "interrupt");
    }

    #[cfg(unix)]
    #[test]
    fn terminal_quit_kills_the_isolated_tree() {
        assert_termination_kills_the_isolated_tree(libc::SIGQUIT, "quit");
    }

    #[cfg(unix)]
    #[test]
    fn an_inherited_ignored_sighup_stays_ignored() {
        let mut helper = spawn_signal_helper("nohup", true, true);
        let pid = helper.pid();
        // SAFETY: the helper owns a dedicated process group.
        assert_eq!(unsafe { libc::kill(-pid, libc::SIGHUP) }, 0);
        let status = wait_for_exit(&mut helper.child, Duration::from_secs(10))
            .expect("ignored SIGHUP helper completes normally");
        let survived = helper.marker.exists();
        let diagnostic = helper.diagnostic();
        helper.complete();
        assert!(status.success(), "helper status: {status}\n{diagnostic}");
        assert!(survived, "nohup-style SIGHUP unexpectedly killed the agent");
    }

    #[cfg(unix)]
    #[test]
    fn an_inherited_custom_signal_handler_is_preserved() {
        let mut helper = spawn_signal_helper("custom-handler", true, false);
        let status = wait_for_exit(&mut helper.child, Duration::from_secs(10))
            .expect("custom-handler helper completes normally");
        let diagnostic = helper.diagnostic();
        helper.complete();
        assert!(status.success(), "helper status: {status}\n{diagnostic}");
    }

    #[cfg(unix)]
    #[test]
    fn a_custom_job_control_callback_never_runs_in_the_guard() {
        let mut helper = spawn_signal_helper("custom-job-control", true, false);
        let pid = helper.pid();
        assert_eq!(unsafe { libc::kill(-pid, libc::SIGTSTP) }, 0);
        let status = wait_for_exit(&mut helper.child, Duration::from_secs(10))
            .expect("custom job-control helper completes normally");
        let diagnostic = helper.diagnostic();
        helper.complete();
        assert!(status.success(), "helper status: {status}\n{diagnostic}");
    }

    #[cfg(unix)]
    #[test]
    fn a_host_owned_sigcont_rejects_default_stop_proxying_before_launch() {
        use std::os::unix::process::CommandExt;

        let scratch = std::env::temp_dir().join(format!(
            "tactus-proc-custom-cont-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&scratch).expect("custom-cont scratch");
        let ready = scratch.join("ready");
        let output = Command::new(std::env::current_exe().expect("test executable"))
            .args(["terminal_interrupt_helper", "--ignored", "--nocapture"])
            .env("TACTUS_SIGNAL_HELPER", "1")
            .env("TACTUS_CUSTOM_CONTINUE_HANDLER", "1")
            .env("TACTUS_EXPECT_JOB_CONTROL_REFUSAL", "1")
            .env("TACTUS_READY", &ready)
            .env("TACTUS_MARKER", scratch.join("marker"))
            .env("TACTUS_FINISH", scratch.join("finish"))
            .process_group(0)
            .output()
            .expect("run custom-SIGCONT policy helper");
        assert!(
            output.status.success(),
            "custom-SIGCONT helper failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !ready.exists(),
            "an agent launched under the unsafe signal policy"
        );
        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[cfg(unix)]
    #[test]
    fn arbitrary_host_callbacks_never_run_in_private_helpers() {
        let mut helper = spawn_signal_helper("custom-aux-signal", true, false);
        let parent = helper.pid();
        let reaper: i32 = std::fs::read_to_string(&helper.reaper_pid_path)
            .expect("recorded private reaper pid")
            .trim()
            .parse()
            .expect("numeric private reaper pid");

        // The helper parent deliberately retains and observes its host-owned
        // callback. The guard shares this group but must have scrubbed the
        // fork-copied callback before unblocking signals.
        assert_eq!(unsafe { libc::kill(-parent, libc::SIGUSR1) }, 0);
        // The private cleanup reaper is in its own group; target it directly so
        // both fork-only helper types prove the same callback boundary.
        assert_eq!(unsafe { libc::kill(reaper, libc::SIGUSR1) }, 0);
        thread::sleep(Duration::from_millis(50));
        std::fs::write(&helper.finish, "finish").expect("release supervised worker");

        let status = wait_for_exit(&mut helper.child, Duration::from_secs(10))
            .expect("host-callback helper completes normally");
        let diagnostic = helper.diagnostic();
        helper.complete();
        assert!(status.success(), "helper status: {status}\n{diagnostic}");
    }

    #[cfg(unix)]
    #[test]
    fn sigkill_of_tactus_job_still_reaps_the_isolated_agent_group() {
        let mut helper = spawn_signal_helper("job-control", true, false);
        let helper_pgid = helper.pid();
        let agent_pgid = helper.supervised_pgid.expect("supervised group");
        assert_eq!(unsafe { libc::kill(-helper_pgid, libc::SIGKILL) }, 0);
        wait_for_exit(&mut helper.child, Duration::from_secs(10))
            .expect("SIGKILLed helper exits promptly");

        // From here onward the test harness must not kill the agent on drop:
        // only the helper's external reaper is allowed to make progress stop.
        helper.active = false;
        thread::sleep(Duration::from_millis(1300));
        let before = std::fs::read_to_string(&helper.marker).ok();
        thread::sleep(Duration::from_millis(350));
        let after = std::fs::read_to_string(&helper.marker).ok();
        let stopped = before == after;

        // Clean up only after recording the result, so a regression cannot be
        // hidden while still avoiding a leaked worker after a failed test.
        let _ = unsafe { libc::kill(-agent_pgid, libc::SIGKILL) };
        helper.complete();
        assert!(
            stopped,
            "the isolated agent kept running after an uncatchable Tactus SIGKILL"
        );
    }

    #[cfg(unix)]
    #[test]
    fn sigkill_keeps_resume_locked_out_until_agent_cleanup_finishes() {
        let mut helper = spawn_signal_helper("crash-lease", true, false);
        let public = helper.scratch.join("run");
        let helper_pgid = helper.pid();
        assert_eq!(unsafe { libc::kill(-helper_pgid, libc::SIGKILL) }, 0);
        wait_for_exit(&mut helper.child, Duration::from_secs(10))
            .expect("SIGKILLed lock holder exits promptly");

        let error = crate::rundir::RunLock::acquire(&public)
            .expect_err("the reaper-owned cleanup lease must block an overlapping resume");
        assert!(
            error.to_string().contains("already driving run"),
            "unexpected cleanup-lease refusal: {error}"
        );
        assert!(
            crate::rundir::is_running(&public),
            "liveness ignored the reaper-owned cleanup lease"
        );

        let deadline = Instant::now() + Duration::from_secs(5);
        let recovered = loop {
            match crate::rundir::RunLock::acquire(&public) {
                Ok(lock) => break lock,
                Err(error) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(20));
                    drop(error);
                }
                Err(error) => panic!("cleanup lease never released: {error}"),
            }
        };
        drop(recovered);
        helper.complete();
    }

    #[cfg(unix)]
    fn assert_stop_covers_the_isolated_tree(signal: libc::c_int, tag: &str) {
        let mut helper = spawn_signal_helper(tag, true, false);
        let pid = helper.pid();
        wait_for_first_progress(&helper.marker, &format!("signal {signal}"));
        assert_eq!(unsafe { libc::kill(-pid, signal) }, 0);
        assert!(
            wait_for_stop(pid, Duration::from_secs(10)),
            "Tactus did not stop for signal {signal}"
        );

        let before = settled_progress_after_stop(&helper.marker, &format!("signal {signal}"));
        thread::sleep(Duration::from_millis(350));
        let after = std::fs::read_to_string(&helper.marker)
            .unwrap_or_else(|error| panic!("progress after signal {signal}: {error}"));
        assert_eq!(
            after, before,
            "the isolated agent kept making progress while Tactus was stopped by signal {signal}"
        );

        std::fs::write(&helper.finish, "finish").expect("release supervised worker");
        assert_eq!(unsafe { libc::kill(-pid, libc::SIGCONT) }, 0);
        let status = wait_for_exit(&mut helper.child, Duration::from_secs(10))
            .unwrap_or_else(|| panic!("signal {signal} left the supervised tree stranded"));
        let diagnostic = helper.diagnostic();
        helper.complete();
        assert!(status.success(), "helper status: {status}\n{diagnostic}");
    }

    #[cfg(unix)]
    #[test]
    fn terminal_input_and_output_stops_cover_the_isolated_tree() {
        for (signal, tag) in [
            (libc::SIGTTIN, "job-control-ttin"),
            (libc::SIGTTOU, "job-control-ttou"),
        ] {
            assert_stop_covers_the_isolated_tree(signal, tag);
        }
    }

    #[cfg(unix)]
    #[test]
    fn uncatchable_sigstop_covers_the_isolated_tree() {
        assert_stop_covers_the_isolated_tree(libc::SIGSTOP, "job-control-sigstop");
    }

    #[cfg(unix)]
    #[test]
    fn terminal_suspend_and_continue_cover_the_isolated_tree() {
        let mut helper = spawn_signal_helper("job-control", true, false);
        let pid = helper.pid();
        wait_for_first_progress(&helper.marker, "suspend interval");
        // SAFETY: `pid` is the id of the helper's dedicated process group, so
        // this models terminal foreground-group job control without touching
        // the surrounding test runner.
        assert_eq!(unsafe { libc::kill(-pid, libc::SIGTSTP) }, 0);

        assert!(
            wait_for_stop(pid, Duration::from_secs(10)),
            "Tactus did not enter a stopped job-control state"
        );

        let before = settled_progress_after_stop(&helper.marker, "suspend interval");
        thread::sleep(Duration::from_millis(350));
        let after =
            std::fs::read_to_string(&helper.marker).expect("progress after suspend interval");
        assert_eq!(
            after, before,
            "the isolated agent kept making progress while Tactus was suspended"
        );

        std::fs::write(&helper.finish, "finish").expect("release supervised worker after continue");

        // SAFETY: SIGCONT resumes our helper; its installed handler forwards
        // the same transition to the isolated process group.
        assert_eq!(unsafe { libc::kill(-pid, libc::SIGCONT) }, 0);
        let status = wait_for_exit(&mut helper.child, Duration::from_secs(10))
            .expect("continued helper completes normally");
        let resumed = helper.marker.exists();
        let diagnostic = helper.diagnostic();
        helper.complete();
        assert!(status.success(), "helper status: {status}\n{diagnostic}");
        assert!(resumed, "the isolated agent was not continued with Tactus");
    }

    #[cfg(unix)]
    #[test]
    fn an_inherited_blocked_sigcont_still_releases_the_isolated_tree() {
        let mut helper = spawn_signal_helper("job-control-cont-blocked", true, false);
        let pid = helper.pid();
        wait_for_first_progress(&helper.marker, "blocked SIGCONT");
        assert_eq!(unsafe { libc::kill(-pid, libc::SIGTSTP) }, 0);
        assert!(
            wait_for_stop(pid, Duration::from_secs(10)),
            "Tactus did not enter a stopped job-control state"
        );

        let before = settled_progress_after_stop(&helper.marker, "blocked SIGCONT");
        thread::sleep(Duration::from_millis(350));
        let after =
            std::fs::read_to_string(&helper.marker).expect("progress after blocked SIGCONT");
        assert_eq!(
            after, before,
            "the isolated agent kept making progress while Tactus was suspended"
        );

        std::fs::write(&helper.finish, "finish").expect("release supervised worker");
        assert_eq!(unsafe { libc::kill(-pid, libc::SIGCONT) }, 0);
        let status = wait_for_exit(&mut helper.child, Duration::from_secs(10))
            .expect("blocked SIGCONT stranded Tactus or its isolated agent tree");
        let diagnostic = helper.diagnostic();
        helper.complete();
        assert!(status.success(), "helper status: {status}\n{diagnostic}");
    }

    #[cfg(unix)]
    #[test]
    fn a_blocked_terminal_signal_still_wakes_a_suspended_host() {
        let mut helper = spawn_signal_helper("job-control-blocked", true, false);
        let pid = helper.pid();
        assert_eq!(unsafe { libc::kill(-pid, libc::SIGTSTP) }, 0);
        assert!(
            wait_for_stop(pid, Duration::from_secs(10)),
            "Tactus did not enter a stopped job-control state"
        );

        assert_eq!(unsafe { libc::kill(-pid, libc::SIGTERM) }, 0);
        std::fs::write(&helper.finish, "finish").expect("release supervised worker");
        let status = wait_for_exit(&mut helper.child, Duration::from_secs(10))
            .expect("guard with an unblocked mask wakes the suspended host");
        let diagnostic = helper.diagnostic();
        helper.complete();
        assert!(status.success(), "helper status: {status}\n{diagnostic}");
    }

    #[cfg(unix)]
    #[test]
    fn a_custom_terminal_handler_still_wakes_a_suspended_host() {
        let mut helper = spawn_signal_helper("job-control-custom", true, false);
        let pid = helper.pid();
        assert_eq!(unsafe { libc::kill(-pid, libc::SIGTSTP) }, 0);
        assert!(
            wait_for_stop(pid, Duration::from_secs(10)),
            "Tactus did not enter a stopped job-control state"
        );

        assert_eq!(unsafe { libc::kill(-pid, libc::SIGTERM) }, 0);
        std::fs::write(&helper.finish, "finish").expect("release supervised worker");
        let status = wait_for_exit(&mut helper.child, Duration::from_secs(10))
            .expect("guard relay wakes the custom-handler host");
        let diagnostic = helper.diagnostic();
        helper.complete();
        assert!(status.success(), "helper status: {status}\n{diagnostic}");
    }

    #[cfg(unix)]
    #[test]
    fn an_ignored_sighup_does_not_wake_a_suspended_tree() {
        let mut helper = spawn_signal_helper("job-control-nohup", true, true);
        let pid = helper.pid();
        wait_for_first_progress(&helper.marker, "ignored SIGHUP");
        assert_eq!(unsafe { libc::kill(-pid, libc::SIGTSTP) }, 0);
        assert!(
            wait_for_stop(pid, Duration::from_secs(10)),
            "Tactus did not enter a stopped job-control state"
        );
        let before = settled_progress_after_stop(&helper.marker, "ignored SIGHUP");
        assert_eq!(unsafe { libc::kill(-pid, libc::SIGHUP) }, 0);
        thread::sleep(Duration::from_millis(350));
        let after = std::fs::read_to_string(&helper.marker).expect("progress after ignored SIGHUP");
        assert_eq!(after, before, "ignored SIGHUP resumed the suspended agent");

        std::fs::write(&helper.finish, "finish").expect("release supervised worker");
        assert_eq!(unsafe { libc::kill(-pid, libc::SIGCONT) }, 0);
        let status = wait_for_exit(&mut helper.child, Duration::from_secs(10))
            .expect("continued helper completes normally");
        let diagnostic = helper.diagnostic();
        helper.complete();
        assert!(status.success(), "helper status: {status}\n{diagnostic}");
    }

    #[cfg(unix)]
    #[test]
    fn a_continue_racing_with_suspend_cannot_strand_the_tree() {
        let mut helper = spawn_signal_helper("job-control", true, false);
        let pid = helper.pid();
        // Deliver the transition back-to-back, before the monitor can promise
        // whether it has reached its final stop instruction.
        assert_eq!(unsafe { libc::kill(-pid, libc::SIGTSTP) }, 0);
        assert_eq!(unsafe { libc::kill(-pid, libc::SIGCONT) }, 0);
        std::fs::write(&helper.finish, "finish").expect("release supervised worker");

        let status =
            wait_for_exit(&mut helper.child, Duration::from_secs(10)).unwrap_or_else(|| {
                panic!("a continue racing with suspend stranded Tactus or its agent tree");
            });
        let diagnostic = helper.diagnostic();
        helper.complete();
        assert!(status.success(), "helper status: {status}\n{diagnostic}");
    }

    #[cfg(unix)]
    #[test]
    fn termination_racing_with_suspend_still_kills_the_tree() {
        let mut helper = spawn_signal_helper("suspend-termination", false, false);
        let pid = helper.pid();
        assert_eq!(unsafe { libc::kill(-pid, libc::SIGTSTP) }, 0);
        // A terminal signal targets the foreground group. The guard remains
        // runnable and wakes a parent that SIGSTOP may already have committed.
        assert_eq!(unsafe { libc::kill(-pid, libc::SIGTERM) }, 0);
        if wait_for_exit(&mut helper.child, Duration::from_secs(10)).is_none() {
            panic!("termination racing with suspend did not terminate Tactus");
        }
        thread::sleep(Duration::from_millis(1300));
        let leaked = helper.marker.exists();
        helper.complete();
        assert!(!leaked, "the suspended agent tree survived termination");
    }

    #[cfg(unix)]
    #[test]
    fn pid_directed_termination_kills_a_suspended_tree_without_continue() {
        let mut helper = spawn_signal_helper("pid-suspend-termination", false, false);
        let pid = helper.pid();
        assert_eq!(unsafe { libc::kill(-pid, libc::SIGTSTP) }, 0);
        assert!(
            wait_for_stop(pid, Duration::from_secs(10)),
            "Tactus did not enter a stopped job-control state"
        );

        // Target only Tactus, not its foreground group and therefore not the
        // external guard. No external SIGCONT follows: the guard's bounded
        // probe must expose the pending signal to Tactus's handler, then let
        // the ordinary monitor/reaper path settle the whole tree.
        assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
        wait_for_exit(&mut helper.child, Duration::from_secs(10))
            .expect("PID-directed termination did not release the stopped Tactus process");
        thread::sleep(Duration::from_millis(1300));
        let leaked = helper.marker.exists();
        helper.complete();
        assert!(
            !leaked,
            "the isolated agent tree survived PID-directed termination"
        );
    }

    #[test]
    fn missing_binary_is_a_spawn_error() {
        let cmd = Command::new("tactus-definitely-not-a-real-binary");
        let err = run_with_timeout(cmd, "", Duration::from_secs(1)).expect_err("must fail");
        assert!(err.to_string().contains("failed to spawn"));
    }

    // -----------------------------------------------------------------------
    // ST-16 (d) — the Unix reaper kills the dead coordinator's containers
    // -----------------------------------------------------------------------

    /// A disposable coordinator that arms the container scope, starts one
    /// supervised agent, and then waits to be killed.
    ///
    /// A subprocess, because the claim is about what survives a coordinator's
    /// death and this test process must survive to assert it. The `docker` the
    /// scope names is a **recording stub**, so the argument vectors the reaper
    /// actually execs are readable afterwards and the assertion is on a
    /// sequence rather than on "a container went away".
    #[cfg(unix)]
    #[test]
    #[ignore = "subprocess helper"]
    #[allow(clippy::zombie_processes)]
    fn unix_reaper_container_helper() {
        if std::env::var_os("TACTUS_REAPER_CONTAINERS").is_none() {
            return;
        }
        let stub = std::path::PathBuf::from(std::env::var_os("TACTUS_STUB").expect("stub path"));
        let root = std::path::PathBuf::from(std::env::var_os("TACTUS_ROOT").expect("root"));
        let incarnation = std::env::var("TACTUS_INCARNATION").expect("incarnation");
        let agent = std::path::PathBuf::from(std::env::var_os("TACTUS_AGENT").expect("agent path"));

        let scope =
            crate::runner::container::census::ReaperContainerScope::new(stub, &root, &incarnation)
                .expect("a scope");
        super::set_container_reclaim_scope(Some(&scope)).expect("arm the reaper");

        let mut supervisor = termination::Supervisor::begin().expect("start a private reaper");
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "sleep 120"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        supervisor.prepare(&mut command);
        let child = command.spawn().expect("spawn an agent in its own group");
        supervisor
            .register(child.id())
            .expect("register the agent group");
        std::fs::write(&agent, child.id().to_string()).expect("record the agent pid");
        if std::env::var_os("TACTUS_REAPER_CONTAINERS_CLEAN_EXIT").is_some() {
            // The **live**-coordinator half: the invocation is settled the
            // ordinary way and this process exits without dying.
            drop(supervisor);
            return;
        }
        thread::sleep(Duration::from_secs(120));
        std::mem::forget(supervisor);
    }

    /// The Unix reaper kills the dead coordinator's labeled containers.
    ///
    /// ST-16 (d), and `os_matrix`: "the cleanup reaper survives coordinator
    /// death, settles the dead coordinator's process groups **while holding
    /// R28**, and **additionally kills the dead coordinator's labeled
    /// containers**, closing the orphan window".
    ///
    /// Four claims, each separately droppable, and each asserted:
    ///
    /// 1. the selector names **both** `tactus.private_root` and
    ///    `tactus.incarnation`, with two distinct values — a reaper that
    ///    filtered on the private root alone would kill every container of every
    ///    run under `<R>`, including a **live** coordinator's, which is exactly
    ///    what `authoritative_state` forbids;
    /// 2. the order is `ps` → `kill` → `rm --force`, taken from the stub's own
    ///    ordered log;
    /// 3. R28 is **still held** while the kill is in flight — the stub blocks
    ///    inside `kill` and the reaper is observed alive there, so a reaper that
    ///    released its hold and then reclaimed would fail;
    /// 4. the agent group is settled too, so the container half did not replace
    ///    the process half.
    ///
    /// **Second field held constant**: the fixture is run twice with the same
    /// scope, the same stub and the same agent — the only thing that moves is
    /// whether the coordinator **dies** or exits cleanly. On a clean exit the
    /// stub is never invoked at all, which is the assertion that keeps a reaper
    /// from killing a live coordinator's containers on the ordinary settle path.
    #[cfg(unix)]
    #[test]
    fn unix_reaper_kills_labeled_containers() {
        const CONTAINER_ID: &str =
            "c0ffee0000000000000000000000000000000000000000000000000000000001";
        const PRIVATE_ROOT: &str = "/srv/tactus-reaper-fixture/private";
        const INCARNATION: &str = "01KZTAAAAAAAAAAAAAAAAAAAAA";

        fn scratch(tag: &str) -> std::path::PathBuf {
            let dir = std::env::temp_dir().join(format!(
                "tactus-reaper-containers-{tag}-{}-{}",
                std::process::id(),
                crate::ulid::ulid()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("scratch");
            dir
        }
        fn alive(pid: i32) -> bool {
            // SAFETY: signal 0 performs no delivery.
            unsafe { libc::kill(pid, 0) == 0 }
        }
        fn read_pid(path: &std::path::Path, timeout: Duration) -> i32 {
            let deadline = Instant::now() + timeout;
            loop {
                if let Ok(text) = std::fs::read_to_string(path) {
                    if let Ok(pid) = text.trim().parse() {
                        return pid;
                    }
                }
                assert!(
                    Instant::now() < deadline,
                    "{} never carried a pid",
                    path.display()
                );
                thread::sleep(Duration::from_millis(10));
            }
        }
        fn wait_for(path: &std::path::Path, timeout: Duration) -> bool {
            let deadline = Instant::now() + timeout;
            while Instant::now() < deadline {
                if path.exists() {
                    return true;
                }
                thread::sleep(Duration::from_millis(10));
            }
            false
        }

        for coordinator_dies in [true, false] {
            let dir = scratch(if coordinator_dies { "dies" } else { "lives" });
            let stub = dir.join("docker-stub");
            let log = dir.join("argv.log");
            // A recording `docker`. It reports one container the first time it
            // is listed and nothing once that container has been removed, which
            // is what ends the reaper's bounded round loop. `kill` blocks so the
            // R28 assertion has a window to observe.
            std::fs::write(
                &stub,
                format!(
                    "#!/bin/sh\n\
                     printf '%s\\n' \"$*\" >> \"$TACTUS_STUB_DIR/argv.log\"\n\
                     case \"$1\" in\n\
                     ps) [ -f \"$TACTUS_STUB_DIR/removed\" ] || printf '%s\\n' '{CONTAINER_ID}' ;;\n\
                     kill) : > \"$TACTUS_STUB_DIR/killing\"; sleep 1 ;;\n\
                     rm) : > \"$TACTUS_STUB_DIR/removed\" ;;\n\
                     esac\n\
                     exit 0\n"
                )
                .replace("{CONTAINER_ID}", CONTAINER_ID),
            )
            .expect("write the stub");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755))
                    .expect("make the stub executable");
            }

            let agent_path = dir.join("agent");
            let reaper_path = dir.join("reaper");
            let mut coordinator = Command::new(std::env::current_exe().expect("test executable"));
            coordinator
                .args(["unix_reaper_container_helper", "--ignored", "--nocapture"])
                .env("TACTUS_REAPER_CONTAINERS", "1")
                .env("TACTUS_STUB", &stub)
                .env("TACTUS_STUB_DIR", &dir)
                .env("TACTUS_ROOT", PRIVATE_ROOT)
                .env("TACTUS_INCARNATION", INCARNATION)
                .env("TACTUS_AGENT", &agent_path)
                .env("TACTUS_TEST_REAPER_PID_PATH", &reaper_path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            if !coordinator_dies {
                coordinator.env("TACTUS_REAPER_CONTAINERS_CLEAN_EXIT", "1");
            }
            let mut coordinator = coordinator.spawn().expect("spawn a disposable coordinator");

            let agent_pid = read_pid(&agent_path, Duration::from_secs(30));
            let reaper_pid = read_pid(&reaper_path, Duration::from_secs(30));

            if !coordinator_dies {
                // The live half: the coordinator settles its invocation and
                // exits. Nothing may have been killed on its behalf.
                coordinator.wait().expect("reap the coordinator");
                thread::sleep(Duration::from_millis(500));
                assert!(
                    !log.exists(),
                    "the reaper reclaimed a LIVE coordinator's containers on the ordinary \
                     settle path: {:?}",
                    std::fs::read_to_string(&log)
                );
                let _ = std::fs::remove_dir_all(&dir);
                continue;
            }

            assert!(alive(agent_pid), "the agent never started");
            coordinator.kill().expect("hard-kill the coordinator");
            coordinator.wait().expect("reap the coordinator");

            // (3) R28 is still held while the container kill is in flight.
            assert!(
                wait_for(&dir.join("killing"), Duration::from_secs(30)),
                "the reaper never issued a container kill"
            );
            assert!(
                alive(reaper_pid),
                "the reaper exited — releasing its shared cleanup hold — before the container \
                 kill it was in the middle of returned"
            );

            // (2) The order, from the stub's own ordered log.
            let deadline = Instant::now() + Duration::from_secs(30);
            let lines = loop {
                let lines: Vec<String> = std::fs::read_to_string(&log)
                    .unwrap_or_default()
                    .lines()
                    .map(str::to_owned)
                    .collect();
                if lines.len() >= 3 || Instant::now() >= deadline {
                    break lines;
                }
                thread::sleep(Duration::from_millis(20));
            };
            assert!(lines.len() >= 3, "the reaper's docker log is {lines:#?}");
            assert!(lines[0].starts_with("ps "), "{lines:#?}");
            assert_eq!(lines[1], format!("kill {CONTAINER_ID}"), "{lines:#?}");
            assert_eq!(lines[2], format!("rm --force {CONTAINER_ID}"), "{lines:#?}");

            // (1) Both filters, two distinct values.
            let filters: Vec<&str> = lines[0]
                .split_whitespace()
                .filter(|word| word.starts_with("label="))
                .collect();
            assert_eq!(
                filters.len(),
                2,
                "the reaper's selector is `{}`; a filter on the private root alone names every \
                 container of every run under it, including a live coordinator's",
                lines[0]
            );
            assert!(
                filters
                    .iter()
                    .any(|filter| *filter == format!("label=tactus.private_root={PRIVATE_ROOT}"))
            );
            assert!(
                filters
                    .iter()
                    .any(|filter| *filter == format!("label=tactus.incarnation={INCARNATION}"))
            );
            assert_eq!(
                filters
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len(),
                2,
                "two filters carrying one value is one filter"
            );

            // (4) The process half still happened.
            let settled_by = Instant::now() + Duration::from_secs(30);
            while alive(agent_pid) && Instant::now() < settled_by {
                thread::sleep(Duration::from_millis(50));
            }
            let settled = !alive(agent_pid);
            // SAFETY: cleanup for the failing case, a no-op for the passing one.
            unsafe {
                let _ = libc::kill(agent_pid, libc::SIGKILL);
                let _ = libc::kill(-agent_pid, libc::SIGKILL);
            }
            let _ = std::fs::remove_dir_all(&dir);
            assert!(
                settled,
                "the container half replaced the process half: the agent group survived"
            );
        }
    }
}
