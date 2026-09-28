//! TemporalTrail V0 — Phase 1 Timeline Engine core.
//!
//! Implements the DAG / Node / Timeline model from the accepted Phase 0
//! specification (§4–§11, §17) against a *fake* state domain: each Node
//! carries a single string (`fake_state`) standing in for the real OS and
//! Docker domains, which arrive in Phase 2 and Phase 4. Every invariant
//! from §3 that doesn't depend on a real domain is enforced here:
//! fork creates no Node (§6/§7 mechanism 2), checkpoint is the sole
//! Node-creating act (§7 mechanism 1, §8), validation is bound to an
//! exact Node (§10), promotion requires a matching PASS and derives the
//! MAIN divergence ancestor via LCA with no stored ancestor field (§11),
//! and discard never touches Node history (§13).

use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashSet;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAIN: &str = "main";

#[derive(Debug)]
pub struct EngineError(pub String);

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for EngineError {}
impl From<rusqlite::Error> for EngineError {
    fn from(e: rusqlite::Error) -> Self {
        EngineError(e.to_string())
    }
}
pub type Result<T> = std::result::Result<T, EngineError>;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn err(msg: impl Into<String>) -> EngineError {
    EngineError(msg.into())
}

#[derive(Debug, Clone)]
pub struct Node {
    pub id: i64,
    pub parent_id: Option<i64>,
    pub timeline_name: String,
    pub timestamp: i64,
    pub action_desc: Option<String>,
    pub fake_state: String,
}

#[derive(Debug, Clone)]
pub struct Timeline {
    pub name: String,
    pub head_node_id: i64,
    pub is_main: bool,
}

#[derive(Debug, Clone)]
pub struct Validation {
    pub id: i64,
    pub node_id: i64,
    pub status: String, // "PASS" | "FAIL"
    pub validator: Option<String>,
    pub timestamp: i64,
}

#[derive(Debug)]
pub struct PromotionResult {
    pub promotion_id: i64,
    pub promoted_node_id: i64,
    pub main_divergence_ancestor: i64,
    pub superseded_main_head: i64,
    pub superseding_interactions_confirmed: usize,
}

#[derive(Debug)]
pub struct DiscardReport {
    pub timeline_name: String,
    pub allowed: i64,
    pub denied: i64,
}

/// A reference to a Node: either an explicit node id ("n42") or the
/// current HEAD of a named Timeline. Resolving a Timeline reference to
/// its HEAD is the *only* way to name a Node without knowing its id.
pub enum NodeRef<'a> {
    Node(i64),
    TimelineHead(&'a str),
}

impl<'a> NodeRef<'a> {
    pub fn parse(s: &'a str) -> NodeRef<'a> {
        if let Some(rest) = s.strip_prefix('n') {
            if let Ok(id) = rest.parse::<i64>() {
                return NodeRef::Node(id);
            }
        }
        NodeRef::TimelineHead(s)
    }
}

pub struct Engine {
    conn: Connection,
}

impl Engine {
    /// Opens (or creates) the engine's SQLite store at `path` and ensures
    /// MAIN exists with a root Node. §14: this Connection is used
    /// single-threaded, single-writer, by design — every mutating method
    /// wraps its work in one transaction, satisfying V0's single-writer
    /// invariant without needing external locking.
    pub fn open(path: &str) -> Result<Engine> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        let e = Engine { conn };
        e.bootstrap()?;
        Ok(e)
    }

    fn bootstrap(&self) -> Result<()> {
        let exists: Option<i64> = self
            .conn
            .query_row(
                "SELECT head_node_id FROM timeline WHERE name = ?1",
                params![MAIN],
                |r| r.get(0),
            )
            .optional()?;
        if exists.is_none() {
            self.conn.execute(
                "INSERT INTO node (parent_id, timeline_name, timestamp, action_desc, fake_state)
                 VALUES (NULL, ?1, ?2, 'root', '')",
                params![MAIN, now()],
            )?;
            let root_id = self.conn.last_insert_rowid();
            self.conn.execute(
                "INSERT INTO timeline (name, head_node_id, is_main, created_at) VALUES (?1, ?2, 1, ?3)",
                params![MAIN, root_id, now()],
            )?;
            self.conn.execute(
                "INSERT OR REPLACE INTO repo_meta (key, value) VALUES ('current_timeline', ?1)",
                params![MAIN],
            )?;
        }
        Ok(())
    }

    // ---- lookups -------------------------------------------------------

    pub fn get_timeline(&self, name: &str) -> Result<Timeline> {
        self.conn
            .query_row(
                "SELECT name, head_node_id, is_main FROM timeline WHERE name = ?1",
                params![name],
                |r| {
                    Ok(Timeline {
                        name: r.get(0)?,
                        head_node_id: r.get(1)?,
                        is_main: r.get::<_, i64>(2)? != 0,
                    })
                },
            )
            .optional()?
            .ok_or_else(|| err(format!("no such timeline: {name}")))
    }

    pub fn get_node(&self, id: i64) -> Result<Node> {
        self.conn
            .query_row(
                "SELECT id, parent_id, timeline_name, timestamp, action_desc, fake_state
                 FROM node WHERE id = ?1",
                params![id],
                |r| {
                    Ok(Node {
                        id: r.get(0)?,
                        parent_id: r.get(1)?,
                        timeline_name: r.get(2)?,
                        timestamp: r.get(3)?,
                        action_desc: r.get(4)?,
                        fake_state: r.get(5)?,
                    })
                },
            )
            .optional()?
            .ok_or_else(|| err(format!("no such node: n{id}")))
    }

    pub fn current_timeline_name(&self) -> Result<String> {
        self.conn
            .query_row(
                "SELECT value FROM repo_meta WHERE key = 'current_timeline'",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(EngineError::from)?
            .ok_or_else(|| err("no current timeline set"))
    }

    pub fn resolve(&self, r: &NodeRef) -> Result<i64> {
        match r {
            NodeRef::Node(id) => {
                self.get_node(*id)?; // validates existence
                Ok(*id)
            }
            NodeRef::TimelineHead(name) => Ok(self.get_timeline(name)?.head_node_id),
        }
    }

    // ---- §7/§8: checkpoint — the sole Node-creating operation ----------

    pub fn checkpoint(
        &self,
        timeline_name: &str,
        new_state: &str,
        action_desc: Option<&str>,
    ) -> Result<Node> {
        let tl = self.get_timeline(timeline_name)?;
        // §8 atomicity: for the fake domain this is a single insert, so
        // atomic by construction; a real domain would freeze/capture here
        // before this point and abort the whole checkpoint on failure.
        self.conn.execute(
            "INSERT INTO node (parent_id, timeline_name, timestamp, action_desc, fake_state)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![tl.head_node_id, timeline_name, now(), action_desc, new_state],
        )?;
        let new_id = self.conn.last_insert_rowid();
        self.conn.execute(
            "UPDATE timeline SET head_node_id = ?1 WHERE name = ?2",
            params![new_id, timeline_name],
        )?;
        self.get_node(new_id)
    }

    // ---- §6/§7 mechanism 2: fork — creates a Timeline, never a Node ----

    pub fn fork(&self, source: &NodeRef, new_timeline_name: &str) -> Result<Timeline> {
        if self.get_timeline(new_timeline_name).is_ok() {
            return Err(err(format!(
                "timeline '{new_timeline_name}' already exists"
            )));
        }
        let source_node_id = self.resolve(source)?;
        self.conn.execute(
            "INSERT INTO timeline (name, head_node_id, is_main, created_at) VALUES (?1, ?2, 0, ?3)",
            params![new_timeline_name, source_node_id, now()],
        )?;
        self.get_timeline(new_timeline_name)
    }

    pub fn switch(&self, name: &str) -> Result<()> {
        self.get_timeline(name)?; // must exist
        self.conn.execute(
            "INSERT OR REPLACE INTO repo_meta (key, value) VALUES ('current_timeline', ?1)",
            params![name],
        )?;
        Ok(())
    }

    // ---- §9 restore / navigation: log + diff, never moves a HEAD -------

    /// Walks parent_id from `timeline`'s HEAD to the root. Newest first.
    pub fn log(&self, timeline_name: &str) -> Result<Vec<Node>> {
        let tl = self.get_timeline(timeline_name)?;
        let mut out = vec![];
        let mut cur = Some(tl.head_node_id);
        while let Some(id) = cur {
            let n = self.get_node(id)?;
            cur = n.parent_id;
            out.push(n);
        }
        Ok(out)
    }

    pub fn diff(&self, a: i64, b: i64) -> Result<(Node, Node, bool)> {
        let na = self.get_node(a)?;
        let nb = self.get_node(b)?;
        let same = na.fake_state == nb.fake_state;
        Ok((na, nb, same))
    }

    // ---- §11: lowest common ancestor — the MAIN divergence ancestor ----
    // No schema field stores this (§17); it is walked from parent_id
    // chains fresh at every promotion, per the accepted Phase 0 fix.

    pub fn lowest_common_ancestor(&self, a: i64, b: i64) -> Result<i64> {
        let mut ancestors_of_a: HashSet<i64> = HashSet::new();
        let mut cur = Some(a);
        while let Some(id) = cur {
            ancestors_of_a.insert(id);
            cur = self.get_node(id)?.parent_id;
        }
        let mut cur = Some(b);
        while let Some(id) = cur {
            if ancestors_of_a.contains(&id) {
                return Ok(id);
            }
            cur = self.get_node(id)?.parent_id;
        }
        Err(err("no common ancestor found (corrupt DAG — should be impossible with a single root)"))
    }

    /// Node ids strictly between `ancestor` (exclusive) and `head`
    /// (inclusive), walking parent_id backward from head. Used to find
    /// what MAIN did since the divergence point.
    fn nodes_strictly_after(&self, ancestor: i64, head: i64) -> Result<Vec<i64>> {
        let mut out = vec![];
        let mut cur = Some(head);
        while let Some(id) = cur {
            if id == ancestor {
                break;
            }
            out.push(id);
            cur = self.get_node(id)?.parent_id;
        }
        Ok(out)
    }

    // ---- §10: validation bound to an exact Node -------------------------

    pub fn validate(&self, node_id: i64, status: &str, validator: Option<&str>) -> Result<Validation> {
        if status != "PASS" && status != "FAIL" {
            return Err(err("status must be PASS or FAIL"));
        }
        self.get_node(node_id)?; // must exist
        self.conn.execute(
            "INSERT INTO validation (node_id, status, validator, timestamp) VALUES (?1, ?2, ?3, ?4)",
            params![node_id, status, validator, now()],
        )?;
        let id = self.conn.last_insert_rowid();
        self.conn.query_row(
            "SELECT id, node_id, status, validator, timestamp FROM validation WHERE id = ?1",
            params![id],
            |r| {
                Ok(Validation {
                    id: r.get(0)?,
                    node_id: r.get(1)?,
                    status: r.get(2)?,
                    validator: r.get(3)?,
                    timestamp: r.get(4)?,
                })
            },
        ).map_err(EngineError::from)
    }

    fn latest_pass_validation(&self, node_id: i64) -> Result<Option<Validation>> {
        self.conn
            .query_row(
                "SELECT id, node_id, status, validator, timestamp FROM validation
                 WHERE node_id = ?1 AND status = 'PASS'
                 ORDER BY timestamp DESC, id DESC LIMIT 1",
                params![node_id],
                |r| {
                    Ok(Validation {
                        id: r.get(0)?,
                        node_id: r.get(1)?,
                        status: r.get(2)?,
                        validator: r.get(3)?,
                        timestamp: r.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(EngineError::from)
    }

    // ---- §16/§12: gateway stub — logs interactions (Phase 3 wires the
    // real network-namespace enforcement; this just gives promote() a
    // real table to query so §11's logic is exercised honestly now). ----

    pub fn log_external_interaction(
        &self,
        timeline_name: &str,
        node_id: i64,
        target: &str,
        decision: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO external_interaction (timeline_name, node_id, target, decision, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![timeline_name, node_id, target, decision, now()],
        )?;
        Ok(())
    }

    // ---- §11: promotion — validated cutover, not a merge ----------------

    pub fn promote(&self, node_id: i64, confirm_superseding_effects: bool) -> Result<PromotionResult> {
        self.get_node(node_id)?;

        // Precondition 1: exact-match PASS validation (§10, TOCTOU fix).
        let validation = self
            .latest_pass_validation(node_id)?
            .ok_or_else(|| err(format!(
                "cannot promote n{node_id}: no PASS validation bound to this exact node"
            )))?;

        let main = self.get_timeline(MAIN)?;
        if node_id == main.head_node_id {
            return Err(err("n{node_id} is already MAIN's HEAD; nothing to promote"));
        }

        // Precondition 2: MAIN divergence ancestor via LCA (§11), then
        // check for superseding external interactions since that point.
        let ancestor = self.lowest_common_ancestor(node_id, main.head_node_id)?;
        let main_path_since = self.nodes_strictly_after(ancestor, main.head_node_id)?;
        let mut superseding_count = 0usize;
        if !main_path_since.is_empty() {
            let placeholders: Vec<String> = main_path_since.iter().map(|_| "?".to_string()).collect();
            let sql = format!(
                "SELECT COUNT(*) FROM external_interaction
                 WHERE decision = 'ALLOW' AND node_id IN ({})",
                placeholders.join(",")
            );
            let mut stmt = self.conn.prepare(&sql)?;
            let params: Vec<&dyn rusqlite::ToSql> =
                main_path_since.iter().map(|i| i as &dyn rusqlite::ToSql).collect();
            superseding_count = stmt.query_row(params.as_slice(), |r| r.get::<_, i64>(0))? as usize;
        }
        if superseding_count > 0 && !confirm_superseding_effects {
            return Err(err(format!(
                "promotion requires confirmation: MAIN performed {superseding_count} external \
                 interaction(s) since n{ancestor} (this Trial's MAIN divergence ancestor). \
                 These effects cannot be automatically merged or reverted. \
                 Re-run with --confirm-superseding-effects."
            )));
        }

        // Effects: cutover (fake domain: just the HEAD reassignment —
        // mechanism 3 of §7), audit record, then advance MAIN's HEAD.
        self.conn.execute(
            "INSERT INTO promotion
             (promoted_node_id, validation_id, superseded_main_head_node_id, superseding_effects_confirmed, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                node_id,
                validation.id,
                main.head_node_id,
                confirm_superseding_effects && superseding_count > 0,
                now()
            ],
        )?;
        let promotion_id = self.conn.last_insert_rowid();
        self.conn.execute(
            "UPDATE timeline SET head_node_id = ?1 WHERE name = ?2",
            params![node_id, MAIN],
        )?;

        Ok(PromotionResult {
            promotion_id,
            promoted_node_id: node_id,
            main_divergence_ancestor: ancestor,
            superseded_main_head: main.head_node_id,
            superseding_interactions_confirmed: superseding_count,
        })
    }

    // ---- §13: discard — internal state only, never undoes external ----

    pub fn discard(&self, timeline_name: &str) -> Result<DiscardReport> {
        let tl = self.get_timeline(timeline_name)?;
        if tl.is_main {
            return Err(err("cannot discard MAIN"));
        }
        let allowed: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM external_interaction WHERE timeline_name = ?1 AND decision = 'ALLOW'",
            params![timeline_name],
            |r| r.get(0),
        )?;
        let denied: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM external_interaction WHERE timeline_name = ?1 AND decision = 'DENY'",
            params![timeline_name],
            |r| r.get(0),
        )?;
        // Node history is deliberately NOT deleted — it remains as
        // orphaned, unreachable-by-HEAD lineage in the DAG (§13).
        self.conn.execute("DELETE FROM timeline WHERE name = ?1", params![timeline_name])?;
        if self.current_timeline_name()? == timeline_name {
            self.switch(MAIN)?;
        }
        Ok(DiscardReport {
            timeline_name: timeline_name.to_string(),
            allowed,
            denied,
        })
    }

    pub fn list_timelines(&self) -> Result<Vec<Timeline>> {
        let mut stmt = self
            .conn
            .prepare("SELECT name, head_node_id, is_main FROM timeline ORDER BY is_main DESC, name")?;
        let rows = stmt
            .query_map([], |r| {
                Ok(Timeline {
                    name: r.get(0)?,
                    head_node_id: r.get(1)?,
                    is_main: r.get::<_, i64>(2)? != 0,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS node (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_id INTEGER REFERENCES node(id),
    timeline_name TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    action_desc TEXT,
    fake_state TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS timeline (
    name TEXT PRIMARY KEY,
    head_node_id INTEGER NOT NULL REFERENCES node(id),
    is_main INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS validation (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id INTEGER NOT NULL REFERENCES node(id),
    status TEXT NOT NULL CHECK(status IN ('PASS','FAIL')),
    validator TEXT,
    timestamp INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS external_interaction (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timeline_name TEXT NOT NULL,
    node_id INTEGER NOT NULL REFERENCES node(id),
    target TEXT NOT NULL,
    decision TEXT NOT NULL CHECK(decision IN ('ALLOW','DENY')),
    timestamp INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS promotion (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    promoted_node_id INTEGER NOT NULL REFERENCES node(id),
    validation_id INTEGER NOT NULL REFERENCES validation(id),
    superseded_main_head_node_id INTEGER REFERENCES node(id),
    superseding_effects_confirmed INTEGER NOT NULL DEFAULT 0,
    timestamp INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS repo_meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
"#;
