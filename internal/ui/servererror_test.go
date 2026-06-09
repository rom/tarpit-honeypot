package ui

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"testing"
)

func TestServerErrorTimeoutDegrades(t *testing.T) {
	// A query deadline should serve a friendly 503 retry page, not a 500.
	w := httptest.NewRecorder()
	serverError(w, "/remote", fmt.Errorf("query: %w", context.DeadlineExceeded))
	if w.Code != 503 {
		t.Errorf("DeadlineExceeded -> code %d; want 503", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header on the degraded page")
	}

	// A genuine error still 500s.
	w2 := httptest.NewRecorder()
	serverError(w2, "/x", errors.New("disk on fire"))
	if w2.Code != 500 {
		t.Errorf("generic error -> code %d; want 500", w2.Code)
	}

	// A cancelled request writes nothing (client already gone).
	w3 := httptest.NewRecorder()
	serverError(w3, "/y", fmt.Errorf("ctx: %w", context.Canceled))
	if w3.Body.Len() != 0 {
		t.Errorf("cancelled request should not write a body, got %q", w3.Body.String())
	}
}
