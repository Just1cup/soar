// Package clock exists so that time is an argument, not an ambient fact.
// Every SLA test, every dedupe-window test and every "did this expire?" check
// would otherwise be a sleep or a flake.
package clock

import "time"

type Clock interface{ Now() time.Time }

type System struct{}

func (System) Now() time.Time { return time.Now().UTC() }

// Fixed is the test clock. Advance moves it deliberately.
type Fixed struct{ T time.Time }

func (f *Fixed) Now() time.Time          { return f.T }
func (f *Fixed) Advance(d time.Duration) { f.T = f.T.Add(d) }
