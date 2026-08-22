//! `tactus answer <question-id>` — the cross-process answer channel (§12).
//!
//! A question is raised by one process and answered by a person who may be
//! nowhere near it: at another terminal, hours later, or after the run has
//! already ended. So the command does not talk to the engine at all. It writes
//! the answer beside the question, and whichever engine is or will be driving
//! that run picks it up — a live one on its next scheduler turn, or the next
//! `tactus resume`.
//!
//! That indirection is what makes §12's promise ("a run survives its
//! notifier") true of answers as well as delivery.
// LEGACY-EFFECT: this module is in the **frozen legacy section** of
// `effects/allowlist.toml`, which carries its justification and the condition
// under which the section shrinks. `decisions.effect_site_inventory.mechanism` (2).
#![allow(clippy::disallowed_methods)]

use std::path::Path;

use crate::error::TactusError;
use crate::interaction::{self, QuestionRecord};
use crate::ir::{Answer, QuestionId};
use crate::rundir;

/// What the operator said, before it is turned into an [`Answer`].
#[derive(Debug, Clone)]
pub enum Reply {
    /// Pick option N, 1-indexed as the question renders them.
    Option(usize),
    Text(String),
    /// Give up on the task; its dependents will be blocked (§19).
    Decline,
}

/// Where an answer landed, for the caller to report.
#[derive(Debug)]
pub struct Answered {
    pub run_id: String,
    pub question_id: String,
    pub answer: Answer,
    /// Whether a live engine is expected to pick this up on its own.
    pub run_is_live: bool,
}

/// Record an answer to a question, found by id or unambiguous prefix.
pub fn answer(repo_root: &Path, wanted: &str, reply: Reply) -> Result<Answered, TactusError> {
    let found = rundir::find_question(repo_root, wanted)?;
    let id = QuestionId(found.question_id.clone());
    let questions = found.public.join("questions");

    let path = questions.join(format!("{}.json", found.question_id));
    let text = std::fs::read_to_string(&path).map_err(|source| TactusError::Io {
        path: path.clone(),
        source,
    })?;
    let record: QuestionRecord = serde_json::from_str(&text).map_err(|e| TactusError::Parse {
        message: format!("{}: {e}", path.display()),
    })?;

    // Answering twice is a mistake worth catching rather than a last-write-
    // wins race: the first answer may already have driven a retry, and the
    // second would look like it had an effect it cannot have.
    if let Some(existing) = &record.answer {
        return Err(TactusError::Refused {
            message: format!(
                "question {} was already answered ({}). Answers are applied once; if the task \
                 needs different guidance it will raise a new question.",
                found.question_id,
                describe(existing)
            ),
        });
    }

    let answer = match reply {
        Reply::Decline => Answer::Declined,
        Reply::Text(text) => interaction::interpret(&record.question, &text),
        Reply::Option(choice) => {
            interaction::answer_for_option(&record.question, choice).ok_or_else(|| {
                TactusError::Refused {
                    message: format!(
                        "there is no option {choice} on this question; it offers {}",
                        if record.question.options.is_empty() {
                            "none (answer it in your own words instead)".to_owned()
                        } else {
                            // Not `1..N`: every operator of this tool reads
                            // Rust, where that is the range that excludes N.
                            format!("1-{}", record.question.options.len())
                        }
                    ),
                }
            })?
        }
    };

    // An empty reply means "leave it parked" at a prompt (§12), and typing
    // nothing into this command almost certainly means the same — but here it
    // would write a file the engine then ingests as an answer, which is not
    // what the operator asked for.
    if answer == Answer::Unanswered {
        return Err(TactusError::Refused {
            message: "an empty answer would leave the task exactly as it is; pass --text with \
                      the guidance, --option N, or --decline to give up on the task"
                .to_owned(),
        });
    }

    let answers = found.public.join("answers");
    std::fs::create_dir_all(&answers).map_err(|source| TactusError::Io {
        path: answers.clone(),
        source,
    })?;
    interaction::write_answer(&answers, &id, &answer)?;

    let run_is_live = rundir::is_running(&found.public);
    Ok(Answered {
        run_id: found.run_id,
        question_id: found.question_id,
        answer,
        run_is_live,
    })
}

/// Render the question for an operator deciding what to say.
pub fn show(repo_root: &Path, wanted: &str) -> Result<String, TactusError> {
    let found = rundir::find_question(repo_root, wanted)?;
    let path = found
        .public
        .join("questions")
        .join(format!("{}.json", found.question_id));
    let text = std::fs::read_to_string(&path).map_err(|source| TactusError::Io {
        path: path.clone(),
        source,
    })?;
    let record: QuestionRecord = serde_json::from_str(&text).map_err(|e| TactusError::Parse {
        message: format!("{}: {e}", path.display()),
    })?;
    Ok(interaction::render_question(&record.question))
}

fn describe(answer: &Answer) -> String {
    match answer {
        Answer::Answered { text } => format!("\"{}\"", crate::util::head(text, 60)),
        Answer::Declined => "declined".to_owned(),
        Answer::Unanswered => "left parked".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Question, QuestionKind, TaskId};
    use std::path::PathBuf;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tactus-answer-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        dir
    }

    fn seed(repo: &Path, run: &str, id: &str) {
        let public = rundir::public_dir(repo, run);
        let questions = public.join("questions");
        std::fs::create_dir_all(&questions).expect("questions dir");
        // A run only exists once its log records a committed `run_started`:
        // `find_question` scans committed directories, so a fixture that wrote
        // only a question would be answering a question in a husk. Written by
        // hand rather than serialized, so the fixture pins the wire rather than
        // agreeing with whatever the writer happens to produce.
        std::fs::write(
            public.join("events.jsonl"),
            format!(
                "{{\"ts\":\"2026-08-20T00:00:00Z\",\"event\":\"run_started\",\
                 \"data\":{{\"schema\":3,\"run_id\":\"{run}\"}}}}\n"
            ),
        )
        .expect("committed first line");
        let record = QuestionRecord::open(Question {
            id: QuestionId::from(id),
            kind: QuestionKind::Unblock,
            affected_tasks: vec![TaskId::from("t1")],
            context: "every rung failed on the same assertion".to_owned(),
            options: vec!["retry on frontier".to_owned(), "skip it".to_owned()],
        });
        interaction::write_question(&questions, &record).expect("write question");
    }

    #[test]
    fn an_answer_lands_where_the_engine_will_find_it() {
        let repo = scratch("basic").join("repo");
        seed(&repo, "01RUN", "q-01ABC");

        let recorded = answer(
            &repo,
            "q-01A",
            Reply::Text("write it in src/widget.rs".to_owned()),
        )
        .expect("answer by prefix");
        assert_eq!(recorded.run_id, "01RUN");
        assert_eq!(recorded.question_id, "q-01ABC");
        assert!(!recorded.run_is_live, "nothing is driving this run");

        let answers = rundir::public_dir(&repo, "01RUN").join("answers");
        let read = interaction::read_answer(&answers, &QuestionId::from("q-01ABC"))
            .expect("read")
            .expect("present");
        assert_eq!(
            read,
            Answer::Answered {
                text: "write it in src/widget.rs".to_owned()
            }
        );
    }

    #[test]
    fn an_option_number_preserves_the_option_action() {
        let repo = scratch("option").join("repo");
        seed(&repo, "01RUN", "q-1");
        let recorded = answer(&repo, "q-1", Reply::Option(2)).expect("answer");
        assert_eq!(recorded.answer, Answer::Declined);

        // Out of range is refused rather than silently clamped — the operator
        // meant a specific option.
        seed(&repo, "02RUN", "q-2");
        let err = answer(&repo, "q-2", Reply::Option(9)).expect_err("no option 9");
        assert!(err.to_string().contains("1-2"), "got: {err}");
        assert!(
            !err.to_string().contains("1..2"),
            "`1..2` is the range excluding 2 to anyone who writes Rust: {err}"
        );
    }

    #[test]
    fn declining_is_expressible_and_distinct_from_answering() {
        let repo = scratch("decline").join("repo");
        seed(&repo, "01RUN", "q-1");
        let recorded = answer(&repo, "q-1", Reply::Decline).expect("decline");
        assert_eq!(recorded.answer, Answer::Declined);
    }

    #[test]
    fn an_empty_answer_is_refused_rather_than_written() {
        // At a prompt, empty means "leave it parked". Written to a file it
        // would instead be ingested as an answer that changes nothing.
        let repo = scratch("empty").join("repo");
        seed(&repo, "01RUN", "q-1");
        let err = answer(&repo, "q-1", Reply::Text("   ".to_owned())).expect_err("refused");
        assert!(err.to_string().contains("--decline"), "got: {err}");
        assert!(
            !rundir::public_dir(&repo, "01RUN")
                .join("answers")
                .join("q-1.json")
                .exists(),
            "nothing written"
        );
    }

    #[test]
    fn a_question_is_answered_once() {
        let repo = scratch("twice").join("repo");
        seed(&repo, "01RUN", "q-1");

        // Simulate the engine having ingested the first answer and rewritten
        // the payload with it.
        let questions = rundir::public_dir(&repo, "01RUN").join("questions");
        let path = questions.join("q-1.json");
        let mut record: QuestionRecord =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("parse");
        record.answer = Some(Answer::Answered {
            text: "already handled".to_owned(),
        });
        interaction::write_question(&questions, &record).expect("rewrite");

        let err = answer(&repo, "q-1", Reply::Text("again".to_owned())).expect_err("refused");
        assert!(err.to_string().contains("already answered"), "got: {err}");
        assert!(
            err.to_string().contains("already handled"),
            "says what: {err}"
        );
    }

    #[test]
    fn an_unknown_question_says_where_it_looked() {
        let repo = scratch("missing").join("repo");
        seed(&repo, "01RUN", "q-1");
        let err = answer(&repo, "q-nope", Reply::Decline).expect_err("no such question");
        assert!(err.to_string().contains("no question"), "got: {err}");
    }

    #[test]
    fn showing_a_question_renders_its_options() {
        let repo = scratch("show").join("repo");
        seed(&repo, "01RUN", "q-1");
        let rendered = show(&repo, "q-1").expect("show");
        assert!(rendered.contains("1) retry on frontier"), "{rendered}");
        assert!(rendered.contains("t1"), "names what parked: {rendered}");
    }
}
