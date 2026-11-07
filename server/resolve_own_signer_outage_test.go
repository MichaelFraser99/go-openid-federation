package server

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type ownRequestCounter struct {
	next      http.Handler
	wellKnown atomic.Int64
	fetch     atomic.Int64
}

func (c *ownRequestCounter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/.well-known/openid-federation" {
		c.wellKnown.Add(1)
	}
	if r.URL.Path == "/fetch" {
		c.fetch.Add(1)
	}
	c.next.ServeHTTP(w, r)
}

type countingSigner struct {
	josemodel.Signer
	signed *atomic.Int64
}

func (s countingSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.signed.Add(1)
	return s.Signer.Sign(rand, digest, opts)
}

type failingSignerListRetriever struct {
	err         error
	subordinate error
	blocks      bool
}

func (r failingSignerListRetriever) GetSubordinate(ctx context.Context, _ model.EntityIdentifier) (*model.SubordinateConfiguration, error) {
	if r.blocks {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if r.subordinate != nil {
		return nil, r.subordinate
	}
	return nil, model.NewNotFoundError("unknown entity identifier")
}

type countingSubjectResolver struct {
	calls  *atomic.Int64
	failAt int64
	err    error
}

func (r countingSubjectResolver) ResolveEntityIdentifier(ctx context.Context, param model.EntityIdentifierParam, raw string) (*model.EntityIdentifier, error) {
	if param == model.EntityIdentifierParamSub && r.calls.Add(1) == r.failAt {
		return nil, r.err
	}
	return model.StandardEntityIdentifierResolver{}.ResolveEntityIdentifier(ctx, param, raw)
}

func (r failingSignerListRetriever) GetSubordinates(context.Context) (map[model.EntityIdentifier]*model.SubordinateConfiguration, error) {
	return map[model.EntityIdentifier]*model.SubordinateConfiguration{}, nil
}

func (r failingSignerListRetriever) GetSubordinateSigners(context.Context) ([]model.SignerConfiguration, error) {
	return nil, r.err
}

func TestServer_Resolve_ATrustAnchorBuildsItsOwnEntityConfigurationRatherThanFetchingIt(t *testing.T) {
	const signerMarker = "KEY-SERVICE-MARKER-ZZZZ"

	newSigner := func(t *testing.T) josemodel.Signer {
		signer, err := jws.GetSigner(jwa.ES256, nil)
		if err != nil {
			t.Fatalf("failed to build a signer: %v", err)
		}
		return signer
	}

	tests := []struct {
		name          string
		reference     string
		subjectIsLeaf bool
		signerFault   error
		responseBytes int64
		fetchLimit    int
		peerBytes     int64
		padOwn        int
		retrieverErr  error
		storeErr      error
		storeBlocks   bool
		unregistered  bool
		longKid       int
		resolveTime   time.Duration
		resolverCalls int64
		resolverFails error
		signatures    int64
		status        int
		code          string
		description   string
	}{
		{
			name:          "a leaf below the anchor while the anchor can sign",
			reference:     "10.2",
			subjectIsLeaf: true,
			signatures:    3,
			status:        http.StatusOK,
		},
		{
			name:       "the anchor as its own subject while it can sign",
			reference:  "10.2",
			signatures: 2,
			status:     http.StatusOK,
		},
		{
			name:         "the anchor as its own subject while its store cannot list its subordinate signers",
			reference:    "8.9 server_error",
			retrieverErr: model.NewNotFoundError(signerMarker),
			status:       http.StatusInternalServerError,
			code:         model.ServerError,
		},
		{
			name:         "the anchor as its own subject while its store is temporarily unable to list its subordinate signers",
			reference:    "8.9 temporarily_unavailable",
			retrieverErr: fmt.Errorf("%w%s", model.ErrTemporarilyUnavailable, signerMarker),
			status:       http.StatusServiceUnavailable,
			code:         model.TemporarilyUnavailable,
		},
		{
			name:          "a leaf below the anchor while the anchor's signer refuses",
			reference:     "8.9 server_error",
			subjectIsLeaf: true,
			signerFault:   errors.New(signerMarker),
			status:        http.StatusInternalServerError,
			code:          model.ServerError,
		},
		{
			name:        "the anchor as its own subject while its signer refuses",
			reference:   "8.9 server_error",
			signerFault: errors.New(signerMarker),
			status:      http.StatusInternalServerError,
			code:        model.ServerError,
		},
		{
			name:          "a leaf below the anchor while the anchor's signer is temporarily unavailable",
			reference:     "8.9 temporarily_unavailable",
			subjectIsLeaf: true,
			signerFault:   fmt.Errorf("%w%s", model.ErrTemporarilyUnavailable, signerMarker),
			status:        http.StatusServiceUnavailable,
			code:          model.TemporarilyUnavailable,
		},
		{
			name:        "the anchor as its own subject while its signer is temporarily unavailable",
			reference:   "8.9 temporarily_unavailable",
			signerFault: fmt.Errorf("%w%s", model.ErrTemporarilyUnavailable, signerMarker),
			status:      http.StatusServiceUnavailable,
			code:        model.TemporarilyUnavailable,
		},
		{
			name:          "a leaf below the anchor when only the leaf's configuration fits the fetch bound",
			reference:     "18.1",
			subjectIsLeaf: true,
			fetchLimit:    1,
			status:        http.StatusOK,
		},
		{
			name:          "a leaf below the anchor when its own configuration would not fit the peer byte bound beside the leaf's",
			reference:     "18.1",
			subjectIsLeaf: true,
			peerBytes:     32768,
			padOwn:        65536,
			status:        http.StatusOK,
		},
		{
			name:          "a leaf below the anchor whose own entity configuration exceeds the peer response bound",
			reference:     "8.9 server_error",
			subjectIsLeaf: true,
			responseBytes: 2048,
			padOwn:        2048,
			status:        http.StatusInternalServerError,
			code:          model.ServerError,
		},
		{
			name:          "a leaf that names the anchor as its superior but is not one of its subordinates",
			reference:     "8.9 invalid_trust_chain",
			subjectIsLeaf: true,
			unregistered:  true,
			status:        http.StatusBadRequest,
			code:          model.InvalidTrustChain,
			description:   "failed to retrieve a usable subordinate statement for an entity in the trust chain",
		},
		{
			name:          "a leaf below the anchor while the anchor's store is temporarily unavailable",
			reference:     "8.9 temporarily_unavailable",
			subjectIsLeaf: true,
			storeErr:      fmt.Errorf("%w%s", model.ErrTemporarilyUnavailable, signerMarker),
			status:        http.StatusServiceUnavailable,
			code:          model.TemporarilyUnavailable,
		},
		{
			name:          "a leaf below the anchor while the anchor's store fails",
			reference:     "8.9 server_error",
			subjectIsLeaf: true,
			storeErr:      errors.New(signerMarker),
			status:        http.StatusInternalServerError,
			code:          model.ServerError,
		},
		{
			name:          "a leaf below the anchor while the anchor's store does not answer before the resolve deadline",
			reference:     "8.9 temporarily_unavailable",
			subjectIsLeaf: true,
			storeBlocks:   true,
			resolveTime:   300 * time.Millisecond,
			status:        http.StatusServiceUnavailable,
			code:          model.TemporarilyUnavailable,
		},
		{
			name:          "a leaf below the anchor when the leaf's configuration alone exceeds the peer byte bound",
			reference:     "18.1",
			subjectIsLeaf: true,
			peerBytes:     100,
			status:        http.StatusOK,
		},
		{
			name:          "a leaf below the anchor whose subordinate statement exceeds the peer response bound",
			reference:     "8.9 server_error",
			subjectIsLeaf: true,
			responseBytes: 2048,
			longKid:       4096,
			status:        http.StatusInternalServerError,
			code:          model.ServerError,
		},
		{
			name:          "a leaf below the anchor, with the subject resolver consulted for the statement the anchor issues",
			reference:     "8.1.1",
			subjectIsLeaf: true,
			resolverCalls: 2,
			status:        http.StatusOK,
		},
		{
			name:          "a leaf below the anchor while the subject resolver fails for the statement the anchor issues",
			reference:     "8.9 server_error",
			subjectIsLeaf: true,
			resolverCalls: 2,
			resolverFails: errors.New(signerMarker),
			status:        http.StatusInternalServerError,
			code:          model.ServerError,
		},
		{
			name:          "the anchor as its own subject whose entity configuration exceeds the peer response bound",
			reference:     "8.9 server_error",
			responseBytes: 2048,
			padOwn:        2048,
			status:        http.StatusInternalServerError,
			code:          model.ServerError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			anchorSigner := newSigner(t)
			signatures := &atomic.Int64{}
			var signer crypto.Signer = countingSigner{Signer: anchorSigner, signed: signatures}
			if tc.signerFault != nil {
				signer = refusingSigner{public: anchorSigner.Public(), err: tc.signerFault}
			}
			var retriever model.Retriever
			if tc.retrieverErr != nil || tc.storeErr != nil || tc.storeBlocks {
				retriever = failingSignerListRetriever{err: tc.retrieverErr, subordinate: tc.storeErr, blocks: tc.storeBlocks}
			}
			resolverCalls := &atomic.Int64{}
			var resolver model.EntityIdentifierResolver
			if tc.resolverCalls != 0 {
				resolver = countingSubjectResolver{calls: resolverCalls}
				if tc.resolverFails != nil {
					resolver = countingSubjectResolver{calls: resolverCalls, failAt: 2, err: tc.resolverFails}
				}
			}
			var own model.EntityStatement
			if tc.padOwn > 0 {
				own.Metadata = &model.Metadata{FederationMetadata: &model.FederationMetadata{"organization_name": strings.Repeat("a", tc.padOwn)}}
			}
			anchor := NewServer(model.ServerConfiguration{
				EntityConfiguration:         own,
				SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "ta"},
				EntityConfigurationLifetime: 10 * time.Minute,
				IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: 10 * time.Minute},
				Configuration:               model.Configuration{MaxPeerResponseBytes: tc.responseBytes, MaxEntitiesTraversed: tc.fetchLimit, MaxRequestPeerBytes: tc.peerBytes, MaxResolveTime: tc.resolveTime},
				MetadataRetriever:           retriever,
				EntityIdentifierResolver:    resolver,
			})
			mux := http.NewServeMux()
			anchor.Configure(mux)
			counter := &ownRequestCounter{next: mux}
			anchorServer := httptest.NewTLSServer(counter)
			t.Cleanup(anchorServer.Close)
			anchor.SetEntityIdentifier(model.EntityIdentifier(anchorServer.URL))
			anchor.SetHttpClient(anchorServer.Client())

			subject := anchorServer.URL
			if tc.subjectIsLeaf {
				leafSigner := newSigner(t)
				leafJWK, err := jwk.PublicJwk(leafSigner.Public())
				if err != nil {
					t.Fatalf("failed to read the leaf key: %v", err)
				}
				(*leafJWK)["kid"] = "leaf"
				leafMux := http.NewServeMux()
				var leafIdentifier string
				leafMux.HandleFunc("/.well-known/openid-federation", func(w http.ResponseWriter, _ *http.Request) {
					token, err := jwt.New(leafSigner, map[string]any{"kid": "leaf", "typ": "entity-statement+jwt", "alg": "ES256"}, map[string]any{
						"iss":             leafIdentifier,
						"sub":             leafIdentifier,
						"iat":             time.Now().Add(-time.Minute).UTC().Unix(),
						"exp":             time.Now().Add(10 * time.Minute).UTC().Unix(),
						"jwks":            map[string]any{"keys": []any{*leafJWK}},
						"authority_hints": []any{anchorServer.URL},
						"metadata":        map[string]any{"federation_entity": map[string]any{}},
					}, jwt.Opts{Algorithm: jwa.ES256})
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					w.Header().Set("Content-Type", "application/entity-statement+jwt")
					_, _ = w.Write([]byte(*token))
				})
				leaf := httptest.NewTLSServer(leafMux)
				t.Cleanup(leaf.Close)
				leafIdentifier = leaf.URL
				subject = leaf.URL
				registered := []map[string]any{*leafJWK}
				if tc.longKid > 0 {
					padded := map[string]any{}
					for member, value := range *leafJWK {
						padded[member] = value
					}
					padded["kid"] = strings.Repeat("k", tc.longKid)
					registered = append(registered, padded)
				}
				if !tc.unregistered {
					anchor.cfg.IntermediateConfiguration.AddSubordinate(model.EntityIdentifier(leaf.URL), &model.SubordinateConfiguration{
						JWKs: josemodel.Jwks{Keys: registered},
					})
				}
			}

			response, err := anchorServer.Client().Get(anchorServer.URL + "/resolve?sub=" + subject + "&trust_anchor=" + anchorServer.URL)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response: %v", err)
			}

			if got := counter.wellKnown.Load(); got != 0 {
				t.Errorf("[#195] expected the resolver to build its own entity configuration rather than request it, got %d requests to its own well-known endpoint", got)
			}
			if got := counter.fetch.Load(); got != 0 {
				t.Errorf("[#277] expected the resolver to build its own subordinate statement rather than request it, got %d requests to its own fetch endpoint", got)
			}
			if response.StatusCode != tc.status {
				t.Fatalf("[%s] expected %d, got %d %s", tc.reference, tc.status, response.StatusCode, raw)
			}
			if strings.Contains(string(raw), signerMarker) {
				t.Errorf("[%s] the signer's own error text reached the caller: %s", tc.reference, raw)
			}
			if tc.resolverCalls != 0 && resolverCalls.Load() != tc.resolverCalls {
				t.Errorf("[%s] expected the subject resolver consulted for the request's sub and for the statement the anchor issues, got %d calls", tc.reference, resolverCalls.Load())
			}
			if tc.signatures != 0 && signatures.Load() != tc.signatures {
				t.Errorf("[#195] expected the anchor's own entity configuration signed once for the request, got %d signatures where %d were expected", signatures.Load(), tc.signatures)
			}
			if tc.code == "" {
				return
			}
			var answer map[string]string
			if err := json.Unmarshal(raw, &answer); err != nil {
				t.Fatalf("failed to read the error: %v", err)
			}
			if answer["error"] != tc.code {
				t.Errorf("[%s] expected %s, got %s", tc.reference, tc.code, raw)
			}
			if tc.description != "" && answer["error_description"] != tc.description {
				t.Errorf("[%s] expected the answer the fetch endpoint gave over HTTP, %q, got %s", tc.reference, tc.description, raw)
			}
		})
	}
}

func TestServer_Resolve_AnIntermediateBuildsItsOwnEntityConfigurationWithItsAuthorityHints(t *testing.T) {
	const signerMarker = "KEY-SERVICE-MARKER-ZZZZ"

	newSigner := func(t *testing.T) josemodel.Signer {
		signer, err := jws.GetSigner(jwa.ES256, nil)
		if err != nil {
			t.Fatalf("failed to build a signer: %v", err)
		}
		return signer
	}
	publicKey := func(t *testing.T, signer josemodel.Signer, kid string) map[string]any {
		public, err := jwk.PublicJwk(signer.Public())
		if err != nil {
			t.Fatalf("failed to read a public key: %v", err)
		}
		(*public)["kid"] = kid
		return *public
	}
	newAuthority := func(t *testing.T, signer crypto.Signer, kid string) (*Server, *httptest.Server, *ownRequestCounter) {
		authority := NewServer(model.ServerConfiguration{
			SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: kid},
			EntityConfigurationLifetime: 10 * time.Minute,
			IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: 10 * time.Minute},
		})
		mux := http.NewServeMux()
		authority.Configure(mux)
		counter := &ownRequestCounter{next: mux}
		ts := httptest.NewTLSServer(counter)
		t.Cleanup(ts.Close)
		authority.SetEntityIdentifier(model.EntityIdentifier(ts.URL))
		authority.SetHttpClient(ts.Client())
		return authority, ts, counter
	}

	tests := []struct {
		name        string
		reference   string
		signerFault error
		peerBytes   int64
		status      int
		code        string
	}{
		{name: "while the intermediate can sign", reference: "10.2", status: http.StatusOK},
		{name: "while the peers' statements fit the peer byte bound only without the one the intermediate issues", reference: "18.1", peerBytes: 14000, status: http.StatusOK},
		{name: "while the intermediate's signer refuses", reference: "8.9 server_error", signerFault: errors.New(signerMarker), status: http.StatusInternalServerError, code: model.ServerError},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			anchor, anchorServer, _ := newAuthority(t, newSigner(t), "ta")

			intermediateSigner := newSigner(t)
			var signer crypto.Signer = intermediateSigner
			if tc.signerFault != nil {
				signer = refusingSigner{public: intermediateSigner.Public(), err: tc.signerFault}
			}
			intermediate, intermediateServer, counter := newAuthority(t, signer, "ia")
			intermediate.AddAuthorityHint(model.EntityIdentifier(anchorServer.URL))
			intermediate.cfg.MaxRequestPeerBytes = tc.peerBytes
			anchor.cfg.IntermediateConfiguration.AddSubordinate(model.EntityIdentifier(intermediateServer.URL), &model.SubordinateConfiguration{
				JWKs: josemodel.Jwks{Keys: []map[string]any{publicKey(t, intermediateSigner, "ia")}},
			})

			leafSigner := newSigner(t)
			leafJWK := publicKey(t, leafSigner, "leaf")
			leafMux := http.NewServeMux()
			var leafIdentifier string
			leafMux.HandleFunc("/.well-known/openid-federation", func(w http.ResponseWriter, _ *http.Request) {
				token, err := jwt.New(leafSigner, map[string]any{"kid": "leaf", "typ": "entity-statement+jwt", "alg": "ES256"}, map[string]any{
					"iss":             leafIdentifier,
					"sub":             leafIdentifier,
					"iat":             time.Now().Add(-time.Minute).UTC().Unix(),
					"exp":             time.Now().Add(10 * time.Minute).UTC().Unix(),
					"jwks":            map[string]any{"keys": []any{leafJWK}},
					"authority_hints": []any{intermediateServer.URL},
					"metadata":        map[string]any{"federation_entity": map[string]any{}},
				}, jwt.Opts{Algorithm: jwa.ES256})
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/entity-statement+jwt")
				_, _ = w.Write([]byte(*token))
			})
			leaf := httptest.NewTLSServer(leafMux)
			t.Cleanup(leaf.Close)
			leafIdentifier = leaf.URL
			intermediate.cfg.IntermediateConfiguration.AddSubordinate(model.EntityIdentifier(leaf.URL), &model.SubordinateConfiguration{
				JWKs: josemodel.Jwks{Keys: []map[string]any{leafJWK}},
			})

			response, err := intermediateServer.Client().Get(intermediateServer.URL + "/resolve?sub=" + leaf.URL + "&trust_anchor=" + anchorServer.URL)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response: %v", err)
			}

			if got := counter.wellKnown.Load(); got != 0 {
				t.Errorf("[#195] expected the resolver to build its own entity configuration rather than request it, got %d requests to its own well-known endpoint", got)
			}
			if got := counter.fetch.Load(); got != 0 {
				t.Errorf("[#277] expected the resolver to build its own subordinate statement rather than request it, got %d requests to its own fetch endpoint", got)
			}
			if response.StatusCode != tc.status {
				t.Fatalf("[%s] expected %d, got %d %s", tc.reference, tc.status, response.StatusCode, raw)
			}
			if strings.Contains(string(raw), signerMarker) {
				t.Errorf("[%s] the signer's own error text reached the caller: %s", tc.reference, raw)
			}
			if tc.code == "" {
				return
			}
			var answer map[string]string
			if err := json.Unmarshal(raw, &answer); err != nil {
				t.Fatalf("failed to read the error: %v", err)
			}
			if answer["error"] != tc.code {
				t.Errorf("[%s] expected %s, got %s", tc.reference, tc.code, raw)
			}
		})
	}
}
