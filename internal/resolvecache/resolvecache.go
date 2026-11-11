package resolvecache

import (
	"context"
	"errors"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

type entry struct {
	signed    *string
	statement *model.EntityStatement
}

type DeadEnd struct {
	Subject model.EntityIdentifier
	Target  model.EntityIdentifier
}

var ErrOwnFault = errors.New("")

var ErrOwnIssuedFault = errors.New("")

type OwnEntityConfiguration func(ctx context.Context) (*string, *model.EntityStatement, error)

type OwnSubordinateStatement func(ctx context.Context, issuer model.EntityStatement, subject model.EntityIdentifier) (*string, *model.EntityStatement, error)

type Cache struct {
	own            model.EntityIdentifier
	buildOwn       OwnEntityConfiguration
	buildOwnIssued OwnSubordinateStatement
	ownFailure     error
	entries        map[model.EntityIdentifier]entry
	described      map[model.EntityIdentifier]struct{}
	deadEnds       map[DeadEnd]struct{}
	traversed      int
	fetched        int
	peerBytes      int64
}

func New() *Cache {
	return &Cache{
		entries:   map[model.EntityIdentifier]entry{},
		described: map[model.EntityIdentifier]struct{}{},
		deadEnds:  map[DeadEnd]struct{}{},
	}
}

func (c *Cache) SetOwn(identifier model.EntityIdentifier, build OwnEntityConfiguration, issue OwnSubordinateStatement) {
	if c == nil {
		return
	}
	c.own = identifier
	c.buildOwn = nil
	c.ownFailure = nil
	if build != nil {
		c.buildOwn = func(ctx context.Context) (*string, *model.EntityStatement, error) {
			if c.ownFailure != nil {
				return nil, nil, c.ownFailure
			}
			signed, statement, err := build(ctx)
			if err != nil {
				c.ownFailure = err
			}
			return signed, statement, err
		}
	}
	c.buildOwnIssued = issue
}

func (c *Cache) Own(identifier model.EntityIdentifier) (OwnEntityConfiguration, bool) {
	if c == nil || c.buildOwn == nil || identifier != c.own {
		return nil, false
	}
	return c.buildOwn, true
}

func (c *Cache) OwnIssued(issuer model.EntityIdentifier) (OwnSubordinateStatement, bool) {
	if c == nil || c.buildOwnIssued == nil || issuer != c.own {
		return nil, false
	}
	return c.buildOwnIssued, true
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
	delete(c.entries, key.Subject)
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

func (c *Cache) Describe(identifier model.EntityIdentifier) bool {
	if c == nil {
		return true
	}
	if _, described := c.described[identifier]; described {
		return false
	}
	c.described[identifier] = struct{}{}
	return true
}
