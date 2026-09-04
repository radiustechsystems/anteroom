package main

import (
	"strings"
	"testing"
)

func TestCLIUnknownCommand(t *testing.T) {
	err := execute([]string{"statt"})
	if err == nil {
		t.Fatal("a typo must not be treated as serve")
	}
	if !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("want unknown command, got %v", err)
	}
}

func TestCLIHealthcheckIsAVerb(t *testing.T) {
	err := execute([]string{"--healthcheck"})
	if err == nil {
		t.Fatal("expected --healthcheck on the root to be unknown")
	}
	if !strings.Contains(err.Error(), "unknown flag") {
		t.Fatalf("want unknown flag, got %v", err)
	}
}

func TestCLIVerboseIsServeOnly(t *testing.T) {
	err := execute([]string{"validate", "-v", "--config", "/no/such.toml"})
	if err == nil {
		t.Fatal("expected -v on validate to be unknown")
	}
	if !strings.Contains(err.Error(), "unknown shorthand flag") && !strings.Contains(err.Error(), "unknown flag") {
		t.Fatalf("want unknown flag, got %v", err)
	}
}

func TestCLIVersion(t *testing.T) {
	if err := execute([]string{"version"}); err != nil {
		t.Fatal(err)
	}
}

func TestCLIVersionRejectsExtraArgs(t *testing.T) {
	err := execute([]string{"version", "extra"})
	if err == nil {
		t.Fatal("expected extra args to be rejected")
	}
}

func TestCLIValidateMissingConfig(t *testing.T) {
	err := execute([]string{"validate", "--config", "/no/such.toml"})
	if err == nil {
		t.Fatal("expected a config error")
	}
	if !strings.Contains(err.Error(), "/no/such.toml") {
		t.Fatalf("error should name the path: %v", err)
	}
}

func TestCLIHealthcheckMissingConfig(t *testing.T) {
	err := execute([]string{"healthcheck", "-c", "/no/such.toml"})
	if err == nil {
		t.Fatal("expected a config error")
	}
	if !strings.Contains(err.Error(), "/no/such.toml") {
		t.Fatalf("error should name the path: %v", err)
	}
}
