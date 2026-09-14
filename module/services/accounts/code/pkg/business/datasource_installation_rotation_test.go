package business

import "testing"

// The re-check sweep reads one page of the parked set per window. Which page is
// what decides whether the sweep is a safety net or theatre: a source parked for
// a DELETED installation can never regain access, so its id stays in that set
// permanently. Reading a fixed first page every window therefore covers only
// those, once enough of them accumulate, and the live installation whose
// `unsuspend` delivery was lost is never re-checked — the exact failure the
// sweep exists to prevent, arriving silently and getting worse with churn.
func TestRecheckPageOffsetReachesEveryPage(t *testing.T) {
	const batch = 100
	// 250 parked installations is three pages, the last one partial.
	const total = 250
	seen := map[int]bool{}
	// One full rotation is pages windows; walk a few more to prove it keeps
	// cycling rather than drifting off the end.
	for counter := int64(0); counter < 9; counter++ {
		offset := recheckPageOffset(counter, total, batch)
		if offset < 0 || offset >= total {
			t.Fatalf("counter %d produced offset %d, outside the parked set of %d", counter, offset, total)
		}
		if offset%batch != 0 {
			t.Fatalf("counter %d produced offset %d, which is not a page boundary", counter, offset)
		}
		seen[offset] = true
	}
	for _, want := range []int{0, 100, 200} {
		if !seen[want] {
			t.Errorf("offset %d was never reached: an installation on that page is starved forever", want)
		}
	}
}

// Consecutive windows must take consecutive pages. Deriving the page from the
// raw window timestamp instead of a window COUNT is the subtle way to get this
// wrong: the timestamp advances by the window length, so modulo a page count
// sharing a factor with it the offset can stall on one page forever.
func TestRecheckPageOffsetAdvancesWithTheCounter(t *testing.T) {
	const batch = 100
	const total = 250
	first := recheckPageOffset(0, total, batch)
	second := recheckPageOffset(1, total, batch)
	if first == second {
		t.Fatalf("consecutive windows both took offset %d; the sweep never rotates", first)
	}
}

// A set that fits in one page has nothing to rotate through, and must not be
// offset past its only page — that would enqueue nothing at all.
func TestRecheckPageOffsetStaysOnASinglePage(t *testing.T) {
	for _, total := range []int{0, 1, 99, 100} {
		for counter := int64(0); counter < 5; counter++ {
			if got := recheckPageOffset(counter, total, 100); got != 0 {
				t.Fatalf("total %d counter %d: offset %d skipped the only page", total, counter, got)
			}
		}
	}
}
