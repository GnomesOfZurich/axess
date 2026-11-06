//! Bookkeeping of the rows an archive sink keeps refusing, so the retention
//! selection can step past them for a while.

/// How many refusals of one row, with nothing else taken in the same tick,
/// it takes before the row is set aside.
const STRIKES_BEFORE_SKIP: u32 = 3;

/// How long a row the sink keeps refusing is left out of the selection before
/// it is offered again.
const SKIP_FOR: chrono::Duration = chrono::Duration::hours(1);

/// The most rows tracked at once; past it a refused row is retried every tick
/// as before rather than growing the record without bound.
const MAX_TRACKED_ROWS: usize = 10_000;

/// The rows the sink refused, by their id as text: how often, and until when
/// the selection leaves a row out.
#[derive(Default)]
pub(super) struct Skipped {
    rows: std::collections::HashMap<String, RowRefusals>,
}

struct RowRefusals {
    strikes: u32,
    until: Option<chrono::DateTime<chrono::Utc>>,
}

impl Skipped {
    /// Forget skips that ran out, keeping their strikes so one more refusal
    /// sets the row aside again.
    pub(super) fn expire(&mut self, now: chrono::DateTime<chrono::Utc>) {
        for row in self.rows.values_mut() {
            if row.until.is_some_and(|until| until <= now) {
                row.until = None;
            }
        }
    }

    pub(super) fn held(&self) -> usize {
        self.rows.values().filter(|r| r.until.is_some()).count()
    }

    pub(super) fn is_held(&self, id: &str) -> bool {
        self.rows.get(id).is_some_and(|r| r.until.is_some())
    }

    /// Note a refusal of `id`; `certain` when the sink took another row in
    /// the same tick, which shows the row itself is what it refuses.
    pub(super) fn refused(
        &mut self,
        id: String,
        certain: bool,
        now: chrono::DateTime<chrono::Utc>,
    ) {
        if !self.rows.contains_key(&id) && self.rows.len() >= MAX_TRACKED_ROWS {
            return;
        }
        let row = self.rows.entry(id).or_insert(RowRefusals {
            strikes: 0,
            until: None,
        });
        row.strikes += 1;
        if certain || row.strikes >= STRIKES_BEFORE_SKIP {
            row.strikes = STRIKES_BEFORE_SKIP - 1;
            row.until = Some(now + SKIP_FOR);
        }
    }

    pub(super) fn taken(&mut self, id: &str) {
        self.rows.remove(id);
    }
}
