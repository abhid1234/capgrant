// worklease — glob intersection (pure, zero-dependency, no filesystem access).
//
// Decides whether two globs from the committed subset (`**`, `*`, `/`, literals)
// could match a common concrete path. This is the conservative *satisfiability*
// rule used by `check`: two globs overlap iff there EXISTS at least one concrete
// path that matches both — evaluated purely over the glob strings, never the
// working tree, so it is safe for a check that runs *before* the edit (the file
// may not exist yet). Symmetric by construction: overlap(a, b) === overlap(b, a).
//
// The problem is pattern-vs-pattern satisfiability at two levels — across
// segments (`**` spans zero or more whole segments) and within a segment (`*`
// matches any run of characters but never crosses `/`). Each level is a memoized
// two-pointer recursion, bounding work to O(m·n) so stacked `**` cannot blow up.

// Normalize a glob string into an array of segment tokens.
//   - strip a single leading "./"
//   - collapse repeated "/" into one
//   - drop a single trailing "/" (treat `src/auth/` as `src/auth`)
//   - split on "/"
//   - within each non-"**" segment, collapse any run of "*" to a single "*"
//     (so `a**b` → `a*b`); "**" keeps its cross-segment meaning only when it is
//     the entire segment.
function normalize(glob) {
  let g = glob;
  if (g.startsWith("./")) g = g.slice(2);
  g = g.replace(/\/+/g, "/");
  if (g.length > 1 && g.endsWith("/")) g = g.slice(0, -1);
  return g
    .split("/")
    .map((seg) => (seg === "**" ? "**" : seg.replace(/\*+/g, "*")));
}

// Within-segment overlap: do single-segment patterns `a` and `b` generate a
// common string? `*` matches any run of characters (including empty); every
// other character is a case-sensitive literal. Memoized two-pointer over chars.
function segmentOverlap(a, b) {
  const memo = new Map();
  const seg = (i, j) => {
    if (i === a.length && j === b.length) return true;
    const key = i * (b.length + 1) + j;
    if (memo.has(key)) return memo.get(key);
    let res;
    if (i < a.length && a[i] === "*") {
      // `*` consumes zero chars of `b`, or one-or-more (advance `b`).
      res = seg(i + 1, j) || (j < b.length && seg(i, j + 1));
    } else if (j < b.length && b[j] === "*") {
      res = seg(i, j + 1) || (i < a.length && seg(i + 1, j));
    } else if (i === a.length || j === b.length) {
      res = false; // one side ran out with a literal still pending
    } else if (a[i] === b[j]) {
      res = seg(i + 1, j + 1);
    } else {
      res = false;
    }
    memo.set(key, res);
    return res;
  };
  return seg(0, 0);
}

// Segment-level overlap: `A`, `B` are segment-token arrays. A token is either
// the literal "**" (matches zero or more whole segments) or a single-segment
// pattern. Memoized on (i, j) so "**"-vs-"**" stays O(|A|·|B|).
function segmentsOverlap(A, B) {
  const memo = new Map();
  const overlap = (i, j) => {
    if (i === A.length && j === B.length) return true;
    const key = i * (B.length + 1) + j;
    if (memo.has(key)) return memo.get(key);
    let res;
    if (i < A.length && A[i] === "**") {
      // "**" matches zero segments, or one-or-more (consume a B segment).
      res = overlap(i + 1, j) || (j < B.length && overlap(i, j + 1));
    } else if (j < B.length && B[j] === "**") {
      res = overlap(i, j + 1) || (i < A.length && overlap(i + 1, j));
    } else if (i === A.length || j === B.length) {
      res = false; // one side ran out with a real segment still pending
    } else if (!segmentOverlap(A[i], B[j])) {
      res = false; // this pair of segments can't align
    } else {
      res = overlap(i + 1, j + 1); // aligned — advance both
    }
    memo.set(key, res);
    return res;
  };
  return overlap(0, 0);
}

// Public API: do two globs share at least one concrete matching path?
export function globsOverlap(globA, globB) {
  return segmentsOverlap(normalize(globA), normalize(globB));
}

// --- directional containment (child ⊆ parent) -------------------------------
// Delegation must PROVE the child pattern authorizes no path the parent doesn't
// — an existential overlap is not enough (`src/*.js` overlaps `src/**` on
// `src/a.js`, yet `src/**` also matches `src/a/b.py`, which `src/*.js` never
// authorizes). These are the asymmetric analogues of the overlap functions.

// segmentContains(p, c): does within-segment pattern `p` match EVERY string that
// `c` matches? `*` = any run of non-slash chars. A `c` `*` can emit a character
// that a `p` literal can't match, so it must be absorbed by a `p` `*`.
function segmentContains(p, c) {
  const memo = new Map();
  const sc = (i, j) => {
    const key = i * (c.length + 1) + j;
    if (memo.has(key)) return memo.get(key);
    let res;
    if (j === c.length) {
      res = true; // c-suffix is "" → p must match "" → all remaining p are '*'
      for (let k = i; k < p.length; k++) if (p[k] !== "*") { res = false; break; }
    } else if (i < p.length && p[i] === "*") {
      res = sc(i + 1, j) || sc(i, j + 1); // end the p-star, or absorb one c unit
    } else if (c[j] === "*") {
      res = false; // c-star can emit a char no p-literal covers
    } else if (i === p.length) {
      res = false; // p exhausted, c literal pending
    } else if (p[i] === c[j]) {
      res = sc(i + 1, j + 1);
    } else {
      res = false;
    }
    memo.set(key, res);
    return res;
  };
  return sc(0, 0);
}

// segmentsContains(P, C): does token-array `P` match EVERY path that `C` matches?
// `**` spans zero+ whole segments; a `C` `**` spans an unbounded segment count a
// single `P` segment can never contain.
function segmentsContains(P, C) {
  const memo = new Map();
  const sc = (i, j) => {
    const key = i * (C.length + 1) + j;
    if (memo.has(key)) return memo.get(key);
    let res;
    if (j === C.length) {
      res = true; // C-suffix is the empty path → remaining P must all be '**'
      for (let k = i; k < P.length; k++) if (P[k] !== "**") { res = false; break; }
    } else if (i < P.length && P[i] === "**") {
      res = sc(i + 1, j) || sc(i, j + 1); // end the P-**, or absorb one C unit
    } else if (C[j] === "**") {
      res = false; // C spans unbounded segments; a single P segment can't contain it
    } else if (i === P.length) {
      res = false;
    } else if (segmentContains(P[i], C[j])) {
      res = sc(i + 1, j + 1);
    } else {
      res = false;
    }
    memo.set(key, res);
    return res;
  };
  return sc(0, 0);
}

// globContains(parent, child) → does EVERY concrete path matched by `child` also
// match `parent`? The directional (asymmetric) check delegation needs.
export function globContains(parentGlob, childGlob) {
  return segmentsContains(normalize(parentGlob), normalize(childGlob));
}
