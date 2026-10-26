package subordinate_statement

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestNew_DoesNotMutateTheConfigurationItIsGiven(t *testing.T) {
	good := map[string]any{"kid": "good", "kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB"}
	leaked := map[string]any{"kid": "leaked", "kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB", "d": "SECRETEXPONENT"}

	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatal(err)
	}

	registered := &model.SubordinateConfiguration{
		JWKs: josemodel.Jwks{Keys: []map[string]any{good, leaked}},
	}
	retriever := func() (*model.SubordinateConfiguration, *model.SignerConfiguration, error) {
		return registered, &model.SignerConfiguration{Signer: signer, KeyID: "ta", Algorithm: "ES256"}, nil
	}

	cfg := model.ServerConfiguration{
		EntityIdentifier:          "https://ta.example.com",
		IntermediateConfiguration: &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Hour},
	}

	const callers = 32
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	payloads := make(chan string, callers)
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := New(t.Context(), "https://leaf.example.com", retriever, cfg)
			if err != nil {
				errs <- err
				return
			}
			payloads <- *token
		}()
	}
	wg.Wait()
	close(errs)
	close(payloads)

	for err := range errs {
		t.Fatalf("every concurrent caller must get a statement, got %v", err)
	}

	issued := 0
	for payload := range payloads {
		issued++
		body := publishedPayload(t, payload)
		if strings.Contains(body, "SECRETEXPONENT") {
			t.Fatalf("a concurrent caller was served the dropped key")
		}
		if !strings.Contains(body, "good") {
			t.Errorf("a concurrent caller was served no usable key")
		}
	}
	if issued != callers {
		t.Fatalf("expected %d statements, got %d", callers, issued)
	}

	if len(registered.JWKs.Keys) != 2 {
		t.Errorf("issuance rewrote the key set its caller registered, which is shared through the subordinate cache: %d keys left of 2", len(registered.JWKs.Keys))
	}
}
