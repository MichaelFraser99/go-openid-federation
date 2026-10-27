package resolvecache

import "github.com/MichaelFraser99/go-openid-federation/model"

type entry struct {
	signed    *string
	statement *model.EntityStatement
}

type DeadEnd struct {
	Subject model.EntityIdentifier
	Target  model.EntityIdentifier
}

type Cache struct {
	entries   map[model.EntityIdentifier]entry
	deadEnds  map[DeadEnd]struct{}
	traversed int
	fetched   int
	peerBytes int64
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

func (c *Cache) IsDeadEnd(key DeadEnd) bool {
	if c == nil {
		return false
	}
	_, known := c.deadEnds[key]
	return known
}

func (c *Cache) RecordDeadEnd(key DeadEnd) {
	if c == nil {
		return
	}
	if c.deadEnds == nil {
		c.deadEnds = map[DeadEnd]struct{}{}
	}
	c.deadEnds[key] = struct{}{}
}

func (c *Cache) DeadEnds() int {
	if c == nil {
		return 0
	}
	return len(c.deadEnds)
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

func (c *Cache) Fetched() int {
	if c == nil {
		return 0
	}
	return c.fetched
}

func (c *Cache) RecordFetch() int {
	if c == nil {
		return 0
	}
	c.fetched++
	return c.fetched
}

func (c *Cache) PeerBytes() int64 {
	if c == nil {
		return 0
	}
	return c.peerBytes
}

func (c *Cache) RecordPeerBytes(n int64) int64 {
	if c == nil {
		return 0
	}
	c.peerBytes += n
	return c.peerBytes
}
