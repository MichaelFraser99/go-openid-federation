package resolvecache

import "github.com/MichaelFraser99/go-openid-federation/model"

type entry struct {
	signed    *string
	statement *model.EntityStatement
}

type DeadEnd struct {
	Subject   model.EntityIdentifier
	Remaining int
}

type Cache struct {
	entries   map[model.EntityIdentifier]entry
	deadEnds  map[DeadEnd]struct{}
	traversed int
}

func New() *Cache {
	return &Cache{
		entries:  map[model.EntityIdentifier]entry{},
		deadEnds: map[DeadEnd]struct{}{},
	}
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

func (c *Cache) DeadEnds() map[DeadEnd]struct{} {
	if c == nil {
		return map[DeadEnd]struct{}{}
	}
	if c.deadEnds == nil {
		c.deadEnds = map[DeadEnd]struct{}{}
	}
	return c.deadEnds
}

func (c *Cache) Traversed() int {
	if c == nil {
		return 0
	}
	return c.traversed
}

func (c *Cache) RecordTraversal() int {
	if c == nil {
		return 0
	}
	c.traversed++
	return c.traversed
}
