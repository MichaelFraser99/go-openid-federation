package resolvecache

import (
	"context"
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

func TestCache_DeadEndsAreKeyedBySubjectAndTarget(t *testing.T) {
	tests := map[string]struct {
		record DeadEnd
		lookup DeadEnd
		want   bool
	}{
		"the recorded pair is a dead end": {
			record: DeadEnd{Subject: "https://a.com", Target: "https://ta.com"},
			lookup: DeadEnd{Subject: "https://a.com", Target: "https://ta.com"},
			want:   true,
		},
		"the same subject under another trust anchor is not": {
			record: DeadEnd{Subject: "https://a.com", Target: "https://ta.com"},
			lookup: DeadEnd{Subject: "https://a.com", Target: "https://other.com"},
			want:   false,
		},
		"another subject under the same trust anchor is not": {
			record: DeadEnd{Subject: "https://a.com", Target: "https://ta.com"},
			lookup: DeadEnd{Subject: "https://b.com", Target: "https://ta.com"},
			want:   false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			c := New()
			c.RecordDeadEnd(tc.record)
			if got := c.IsDeadEnd(tc.lookup); got != tc.want {
				t.Errorf("expected dead end %v, got %v", tc.want, got)
			}
		})
	}
}

func TestCache_CountersAreNilSafeAndMonotone(t *testing.T) {
	var absent *Cache
	if got := absent.RecordTraversal(); got != 0 {
		t.Errorf("expected no accounting without a cache, got %d", got)
	}
	if got := absent.RecordFetch(); got != 0 {
		t.Errorf("expected no accounting without a cache, got %d", got)
	}
	absent.RecordDeadEnd(DeadEnd{Subject: "https://a.com"})
	if absent.IsDeadEnd(DeadEnd{Subject: "https://a.com"}) {
		t.Error("expected nothing to be remembered without a cache")
	}

	c := New()
	for i := range 3 {
		if got := c.RecordTraversal(); got != i+1 {
			t.Errorf("expected traversal %d, got %d", i+1, got)
		}
		if got := c.RecordFetch(); got != i+1 {
			t.Errorf("expected fetch %d, got %d", i+1, got)
		}
	}
	if c.Traversed() != 3 || c.Fetched() != 3 {
		t.Errorf("expected 3 traversals and 3 fetches, got %d and %d", c.Traversed(), c.Fetched())
	}
	if absent.Traversed() != 0 || absent.Fetched() != 0 {
		t.Error("expected zero counts without a cache")
	}
}

func TestCache_OwnIsOfferedOnlyForTheIdentifierItWasSetFor(t *testing.T) {
	own := model.EntityIdentifier("https://ta.example.com")
	build := func(context.Context) (*string, *model.EntityStatement, error) { return nil, nil, nil }
	issue := func(context.Context, model.EntityStatement, model.EntityIdentifier) (*string, *model.EntityStatement, error) {
		return nil, nil, nil
	}
	both := func() *Cache { c := New(); c.SetOwn(own, build, issue); return c }

	tests := map[string]struct {
		cache      func() *Cache
		lookup     model.EntityIdentifier
		wantOwn    bool
		wantIssued bool
	}{
		"the identifier it was set for": {
			cache:      both,
			lookup:     own,
			wantOwn:    true,
			wantIssued: true,
		},
		"another identifier": {
			cache:  both,
			lookup: "https://other.example.com",
		},
		"a spelling of the same entity that differs as a string": {
			cache:  both,
			lookup: "https://TA.example.com",
		},
		"the identifier it was set for, with no subordinate statement builder": {
			cache:   func() *Cache { c := New(); c.SetOwn(own, build, nil); return c },
			lookup:  own,
			wantOwn: true,
		},
		"the identifier it was set for, with no entity configuration builder": {
			cache:      func() *Cache { c := New(); c.SetOwn(own, nil, issue); return c },
			lookup:     own,
			wantIssued: true,
		},
		"a cache it was never set on": {
			cache:  New,
			lookup: own,
		},
		"a cache it was never set on, asked for the empty identifier": {
			cache:  New,
			lookup: "",
		},
		"a nil cache": {
			cache:  func() *Cache { return nil },
			lookup: own,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cache := tt.cache()
			got, ok := cache.Own(tt.lookup)
			if ok != tt.wantOwn {
				t.Fatalf("expected the entity configuration builder offered=%t, got %t", tt.wantOwn, ok)
			}
			if ok == (got == nil) {
				t.Errorf("expected a builder exactly when one is offered, got offered=%t builder=%t", ok, got != nil)
			}
			issued, ok := cache.OwnIssued(tt.lookup)
			if ok != tt.wantIssued {
				t.Fatalf("expected the subordinate statement builder offered=%t, got %t", tt.wantIssued, ok)
			}
			if ok == (issued == nil) {
				t.Errorf("expected a builder exactly when one is offered, got offered=%t builder=%t", ok, issued != nil)
			}
		})
	}
}

func TestCache_DescribeIsTrueOncePerIdentifier(t *testing.T) {
	var absent *Cache
	for range 2 {
		if !absent.Describe("https://a.example.com") {
			t.Error("expected a nil cache to remember nothing, so every call describes")
		}
	}

	c := New()
	if !c.Describe("https://a.example.com") {
		t.Error("expected the first call for an identifier to describe it")
	}
	if c.Describe("https://a.example.com") {
		t.Error("expected a second call for the same identifier not to describe it again")
	}
	if !c.Describe("https://b.example.com") {
		t.Error("expected another identifier to be described on its first call")
	}
}
