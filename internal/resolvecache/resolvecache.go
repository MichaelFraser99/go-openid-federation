package resolvecache

import "github.com/MichaelFraser99/go-openid-federation/model"

type entry struct {
	signed    *string
	statement *model.EntityStatement
	err       error
}

// Cache stores Entity Configuration retrievals for the lifetime of a single
// resolve so a repeated look-up reuses the first result instead of re-fetching.
// It is scoped to one request and one goroutine: it performs no locking and
// MUST NOT be shared across concurrent requests. A nil *Cache is valid and
// disables caching, so callers may pass nil to opt out.
type Cache struct {
	entries map[model.EntityIdentifier]entry
}

func New() *Cache {
	return &Cache{entries: map[model.EntityIdentifier]entry{}}
}

func (c *Cache) Load(identifier model.EntityIdentifier) (*string, *model.EntityStatement, error, bool) {
	if c == nil {
		return nil, nil, nil, false
	}
	e, ok := c.entries[identifier]
	return e.signed, e.statement, e.err, ok
}

func (c *Cache) Store(identifier model.EntityIdentifier, signed *string, statement *model.EntityStatement, err error) {
	if c == nil {
		return
	}
	c.entries[identifier] = entry{signed: signed, statement: statement, err: err}
}
