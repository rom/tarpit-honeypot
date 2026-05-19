package sensor

import "time"

// timeNow is a thin indirection over time.Now to make synthetic-event
// timestamps consistent and easier to swap for tests.
func timeNow() time.Time { return time.Now().UTC() }
