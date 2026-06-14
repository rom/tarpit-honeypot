package store

import (
	"database/sql/driver"
	"fmt"
	"regexp"
	"strings"
	"sync"

	sqlite "modernc.org/sqlite"
)

// regexpOr builds the SQL fragment "col REGEXP ? OR col REGEXP ? ..." with n
// placeholders, so a text column (or expression) can be matched against any of
// n patterns. col is always a fixed literal / built expression — never operator
// input; the caller binds the n patterns (already flag-wrapped) as args in
// order.
func regexpOr(col string, n int) string {
	clause := col + " REGEXP ?"
	if n <= 1 {
		return clause
	}
	parts := make([]string, n)
	for i := range parts {
		parts[i] = clause
	}
	return strings.Join(parts, " OR ")
}

// regexpCache memoizes compiled patterns so the REGEXP UDF compiles each
// distinct pattern once per process instead of once per scanned row — a query
// reuses the same handful of patterns across the whole window. Bounded so a
// flood of distinct patterns can't grow it without limit.
var (
	regexpMu    sync.RWMutex
	regexpCache = map[string]*regexp.Regexp{}
)

const regexpCacheMax = 1024

func compileCachedRegexp(pat string) (*regexp.Regexp, error) {
	regexpMu.RLock()
	re, ok := regexpCache[pat]
	regexpMu.RUnlock()
	if ok {
		return re, nil
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		return nil, err
	}
	regexpMu.Lock()
	if len(regexpCache) < regexpCacheMax {
		regexpCache[pat] = re
	}
	regexpMu.Unlock()
	return re, nil
}

// init registers SQLite's REGEXP operator implementation. `X REGEXP Y` is
// sugar for the two-argument function regexp(Y, X) — pattern first, value
// second — which SQLite does not provide on its own. With this registered, a
// Filter set to regex mode can match text columns by RE2 pattern (see
// Filter.Regex). Patterns are expected to arrive already wrapped with any flags
// (the UI binds "(?i)"+pattern for case-insensitive matching).
//
// Registered in init so the function is present on every connection the driver
// opens later (registration only affects connections opened afterwards), and a
// deterministic registration lets SQLite cache results for repeated inputs.
func init() {
	sqlite.MustRegisterDeterministicScalarFunction("regexp", 2, regexpFunc)
}

func regexpFunc(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("regexp: want 2 args, got %d", len(args))
	}
	pat, ok := args[0].(string)
	if !ok || pat == "" {
		// A non-string or empty pattern never matches (rather than erroring the
		// whole query); callers filter empty tokens out before they get here.
		return int64(0), nil
	}
	var val string
	switch t := args[1].(type) {
	case nil:
		return int64(0), nil
	case string:
		val = t
	default:
		val = fmt.Sprintf("%v", t)
	}
	re, err := compileCachedRegexp(pat)
	if err != nil {
		return nil, err
	}
	if re.MatchString(val) {
		return int64(1), nil
	}
	return int64(0), nil
}
