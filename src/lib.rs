//! tactus — headless orchestration engine for AI coding agents.
//!
//! Copyright (C) 2026 Cameron Lambert
//!
//! This program is free software: you can redistribute it and/or modify it
//! under the terms of the GNU Affero General Public License as published by
//! the Free Software Foundation, version 3 of the License. It is distributed
//! WITHOUT ANY WARRANTY; without
//! even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
//! PURPOSE. See the GNU Affero General Public License for more details. You
//! should have received a copy of the License along with this program; if
//! not, see <https://www.gnu.org/licenses/>.
//!
//! Commercial licences are available for use that the AGPL does not permit —
//! see README.md.
//!
//! v0.1 scope (DESIGN.md §21, steps 1–10): parse an annotated markdown plan
//! into the IR, resolve a routing chain per task, and execute it sequentially —
//! one agent subprocess per attempt, gates and read-only review over the
//! engine-captured diff, one commit per task, every transition an event in
//! `events.jsonl`. `resume`, `status`, and `answer` are folds over that log.
//!
//! The capacity engine (§13) ships **read-only**: `connect` discovers the agent
//! CLIs and writes the pools file, `capacity` and the dry-run preview estimate
//! what is left and what each strategy *would* do, and budgets stop a run at a
//! ceiling — but nothing routes on any of it. Capacity-driven binding is v0.2.

pub mod agent;
pub mod answer;
pub mod capacity;
pub mod catalog;
pub mod config;
pub mod connect;
pub mod effects;
pub mod engine;
pub mod error;
pub mod events;
pub mod export;
pub mod gates;
pub mod interaction;
pub mod ir;
pub mod ladder;
pub mod plan;
pub mod review;
pub mod route;
pub mod rundir;
pub mod runner;
pub mod status;
pub mod topology;
pub mod ulid;
pub mod util;
pub mod validate;
pub mod workspace;
pub mod workspace_manager;
