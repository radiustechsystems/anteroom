package logging

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFieldsFromRequestGeneratesID(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	f := FieldsFromRequest(r)
	if len(f.RequestID) != 32 {
		t.Errorf("generated request_id length = %d, want 32 hex chars, got %q", len(f.RequestID), f.RequestID)
	}
	if f.TraceID != "" || f.SpanID != "" {
		t.Errorf("invented a trace: %+v", f)
	}
}

func TestFieldsFromRequestHonorsInboundID(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(HeaderRequestID, "abc-123")
	f := FieldsFromRequest(r)
	if f.RequestID != "abc-123" {
		t.Errorf("request_id = %q", f.RequestID)
	}
}

func TestFieldsFromRequestFallsBackToCorrelationID(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(HeaderCorrelationID, "corr.1")
	f := FieldsFromRequest(r)
	if f.RequestID != "corr.1" {
		t.Errorf("request_id = %q", f.RequestID)
	}
}

func TestFieldsFromRequestRejectsGarbageID(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(HeaderRequestID, "not a valid id\nwith newline")
	f := FieldsFromRequest(r)
	if f.RequestID == "not a valid id\nwith newline" || f.RequestID == "" {
		t.Errorf("garbage id should be replaced, got %q", f.RequestID)
	}
}

func TestParseTraceparent(t *testing.T) {
	const raw = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	tid, sid := parseTraceparent(raw)
	if tid != "0af7651916cd43dd8448eb211c80319c" || sid != "b7ad6b7169203331" {
		t.Errorf("got %s %s", tid, sid)
	}
	tid, sid = parseTraceparent("00-00000000000000000000000000000000-b7ad6b7169203331-01")
	if tid != "" || sid != "" {
		t.Errorf("all-zero trace-id should be rejected, got %s %s", tid, sid)
	}
	tid, sid = parseTraceparent("not-a-traceparent")
	if tid != "" || sid != "" {
		t.Errorf("malformed should be rejected, got %s %s", tid, sid)
	}
}

func TestBindRequestRestatesHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r = BindRequest(r)
	id := r.Header.Get(HeaderRequestID)
	if id == "" {
		t.Fatal("BindRequest did not set X-Request-ID")
	}
	f, ok := FromContext(r.Context())
	if !ok || f.RequestID != id {
		t.Errorf("context Fields = %+v, header %q", f, id)
	}

	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.Header.Set(HeaderRequestID, "keep-me")
	r2.Header.Set(HeaderTraceparent, "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
	r2 = BindRequest(r2)
	if r2.Header.Get(HeaderRequestID) != "keep-me" {
		t.Errorf("inbound id overwritten: %q", r2.Header.Get(HeaderRequestID))
	}
	f, _ = FromContext(r2.Context())
	if f.TraceID != "0af7651916cd43dd8448eb211c80319c" || f.SpanID != "b7ad6b7169203331" {
		t.Errorf("traceparent not parsed: %+v", f)
	}
}
