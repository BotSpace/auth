package config

import "testing"

func setMinimalEnv(t *testing.T) {
	t.Helper()
	t.Setenv("PRIVATE_KEY", "private")
	t.Setenv("PUBLIC_KEY", "public")
	t.Setenv("DATABASE_TYPE", "sqlite")
	t.Setenv("DATABASE_DSN", "")
	t.Setenv("ADDR", "")
}

func TestNewConfigAppliesSafeListenDefault(t *testing.T) {
	setMinimalEnv(t)
	cfg, err := NewConfig()
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if cfg.Addr != ":8080" {
		t.Fatalf("Addr = %q, want :8080", cfg.Addr)
	}
}

func TestNewConfigRejectsUnknownDatabaseType(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("DATABASE_TYPE", "mysql")
	if _, err := NewConfig(); err == nil {
		t.Fatal("expected unsupported database type to fail")
	}
}

func TestNewConfigRequiresPostgresDSN(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("DATABASE_TYPE", "postgres")
	if _, err := NewConfig(); err == nil {
		t.Fatal("expected missing postgres DSN to fail")
	}
}
