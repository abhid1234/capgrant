// capgrant — `audit` core (after-the-fact "did the fleet stay in scope?" score).
//
// The mirror of `check`: where `check` gates ONE action before it happens,
// `audit` replays a whole batch of actions a fleet already took and scores how
// many stayed inside their granted authority. It is the accountability half of
// the format — a grant is only as good as being able to prove, later, that every
// action was covered by a live grant at the moment it ran. Pure: it reuses the
// same `check` decision per action, so `audit` and `check` can never disagree on
// what "in scope" means.

import { check } from "./check.js";

// audit(actions, grants, opts) → { score, total, allowed, violations }
//
//   actions — array of `{ action, resource, subject, at? }`. `at` (ISO string),
//             when present, is the instant the action ran — used as `now` for
//             that action's `check`, so a grant that was live *then* counts even
//             if it has since expired. Absent `at` falls back to `opts.now`.
//   grants  — the resolved registry array (typically loaded with `expire: false`
//             so wall-clock decay doesn't collapse grants the audit must still
//             evaluate against each action's own `at`).
//   opts.now — default instant for actions without an `at` (injected).
//
// Runs `check` per action; a disallowed action becomes a violation carrying the
// specific denial `reason`. `score` = allowed / total (1.0 when there are no
// actions — vacuously in scope).
export function audit(actions, grants, opts = {}) {
  const { now = Date.now() } = opts;
  const list = Array.isArray(actions) ? actions : [];

  let allowed = 0;
  const violations = [];

  for (const a of list) {
    const parsed = a && a.at != null ? Date.parse(a.at) : NaN;
    const at = Number.isNaN(parsed) ? now : parsed;
    const subject = a ? a.subject : undefined;
    const result = check(a ? a.action : undefined, a ? a.resource : undefined, grants, {
      subject,
      now: at,
    });
    if (result.allowed) {
      allowed += 1;
    } else {
      violations.push({
        action: a ? a.action : undefined,
        resource: a ? a.resource : undefined,
        subject,
        reason: result.reason,
      });
    }
  }

  const total = list.length;
  const score = total === 0 ? 1 : allowed / total;
  return { score, total, allowed, violations };
}
