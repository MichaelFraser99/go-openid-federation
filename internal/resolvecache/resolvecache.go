package resolvecache

import "github.com/MichaelFraser99/go-openid-federation/model"

type entry struct {
	signed    *string
	statement *model.EntityStatement
}

type Cache struct {
	entries map[model.EntityIdentifier]entry
}

func New() *Cache {
	return &Cache{entries: map[model.EntityIdentifier]entry{}}
}

func (c *Cache) Load(identifier model.EntityIdentifier) (*string, *model.EntityStatement, bool) {
	if c == nil {
		return nil, nil, false
	}
	e, ok := c.entries[identifier]
	return e.signed, e.statement, ok
}

func (c *Cache) Store(identifier model.EntityIdentifier, signed *string, statement *model.EntityStatement) {
	if c == nil {
		return
	}
	c.entries[identifier] = entry{signed: signed, statement: statement}
}
