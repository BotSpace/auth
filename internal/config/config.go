package config

import (
	"fmt"
	"os"
)

type Config struct {
	PrivateKey     []byte
	PublicKey      []byte
	Addr           string
	AccessExp      int64
	RefreshExp     int64
	GoogleClientID string
	DatabaseDsn    string
	DatabaseType   string
}

func NewConfig() (*Config, error) {
	var privKey []byte
	var pubKey []byte
	var err error
	if os.Getenv("PRIVATE_KEY") != "" {
		privKey = []byte(os.Getenv("PRIVATE_KEY"))
	} else {
		privKey, err = os.ReadFile("keys/private.pem")
		if err != nil {
			return nil, fmt.Errorf("read RSA private key: %w", err)
		}
	}
	if os.Getenv("PUBLIC_KEY") != "" {
		pubKey = []byte(os.Getenv("PUBLIC_KEY"))
	} else {
		pubKey, err = os.ReadFile("keys/public.pem")
		if err != nil {
			return nil, fmt.Errorf("read RSA public key: %w", err)
		}
	}

	cfg := &Config{
		PrivateKey:     privKey,
		PublicKey:      pubKey,
		Addr:           os.Getenv("ADDR"),
		AccessExp:      60,
		RefreshExp:     43200,
		GoogleClientID: os.Getenv("GOOGLE_CLIENT_ID"),
		DatabaseType:   os.Getenv("DATABASE_TYPE"),
		DatabaseDsn:    os.Getenv("DATABASE_DSN"),
	}
	if len(cfg.PrivateKey) == 0 || len(cfg.PublicKey) == 0 {
		return nil, fmt.Errorf("RSA private and public keys must not be empty")
	}
	if cfg.Addr == "" {
		cfg.Addr = ":8080"
	}
	if cfg.DatabaseType != "postgres" && cfg.DatabaseType != "sqlite" {
		return nil, fmt.Errorf("DATABASE_TYPE must be postgres or sqlite")
	}
	if cfg.DatabaseType == "postgres" && cfg.DatabaseDsn == "" {
		return nil, fmt.Errorf("DATABASE_DSN is required for postgres")
	}
	return cfg, nil
}
