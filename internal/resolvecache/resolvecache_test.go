package resolvecache

import (
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestCache_LoadStore(t *testing.T) {
	signed := "signed.jwt.value"
	statement := &model.EntityStatement{Iss: "https://example.com", Sub: "https://example.com"}

	tests := map[string]struct {
		seed     func(c *Cache)
		lookup   model.EntityIdentifier
		wantOK   bool
		wantSign *string
		wantStmt *model.EntityStatement
	}{
		"load returns stored entry": {
			seed:     func(c *Cache) { c.Store("https://example.com", &signed, statement) },
			lookup:   "https://example.com",
			wantOK:   true,
			wantSign: &signed,
			wantStmt: statement,
		},
		"load of unstored identifier misses": {
			seed:   func(c *Cache) {},
			lookup: "https://absent.com",
			wantOK: false,
		},
		"load distinguishes identifiers": {
			seed:     func(c *Cache) { c.Store("https://a.com", &signed, statement) },
			lookup:   "https://b.com",
			wantOK:   false,
			wantSign: nil,
			wantStmt: nil,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			c := New()
			tt.seed(c)

			gotSign, gotStmt, ok := c.Load(tt.lookup)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if gotSign != tt.wantSign {
				t.Errorf("signed = %v, want %v", gotSign, tt.wantSign)
			}
			if gotStmt != tt.wantStmt {
				t.Errorf("statement = %v, want %v", gotStmt, tt.wantStmt)
			}
		})
	}
}

func TestCache_NilSafe(t *testing.T) {
	var c *Cache

	c.Store("https://example.com", nil, nil)

	if _, _, ok := c.Load("https://example.com"); ok {
		t.Fatal("nil cache Load returned ok=true, want false")
	}
}
