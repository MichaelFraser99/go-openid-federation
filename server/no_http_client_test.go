package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestConfigure_SuppliesNoHttpClientOfItsOwn(t *testing.T) {
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(model.ServerConfiguration{
		EntityIdentifier:            "https://ta.example.com",
		SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "ta"},
		EntityConfigurationLifetime: time.Hour,
		IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Hour},
	})
	mux := http.NewServeMux()
	srv.Configure(mux)
	if srv.cfg.HttpClient != nil {
		t.Fatalf("expected Configure to leave HttpClient unset, it installed %T", srv.cfg.HttpClient)
	}
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	response, err := ts.Client().Get(ts.URL + "/resolve?" + url.Values{"sub": {"https://leaf.example.com"}, "trust_anchor": {"https://ta.example.com"}}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close() //nolint:errcheck
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("expected a JSON error body, got %s", raw)
	}
	if response.StatusCode != http.StatusInternalServerError || body.Error != model.ServerError {
		t.Errorf("[8.9] a resolver with no client to fetch with has failed itself, so expected 500 server_error, got %d %s", response.StatusCode, raw)
	}
}
