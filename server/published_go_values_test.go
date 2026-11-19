package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type publishedSerial int64

type publishedCounter struct {
	Total uint64 `json:"total"`
}

type publishedPair struct {
	X int `json:"x"`
}

func publishedGoValues() map[string]any {
	return map[string]any{
		"x_named_int":       publishedSerial(1<<53 + 1),
		"x_max_uint":        publishedCounter{Total: math.MaxUint64},
		"x_bytes":           []byte{0xfb, 0xff, 0x01},
		"x_typed_map":       map[string]publishedPair{"a": {X: 1}},
		"x_typed_map_slice": []map[string]publishedPair{{"b": {X: 2}}},
	}
}

func decodeExactly(t *testing.T, raw []byte) any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatalf("failed to decode %s: %v", raw, err)
	}
	return decoded
}

func publishedClaims(t *testing.T, ts *httptest.Server, path string) map[string]any {
	t.Helper()
	response := get(t, ts, path)
	defer func() { _ = response.Body.Close() }()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("failed to read the response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected the statement, got %d %s", response.StatusCode, raw)
	}
	parts := strings.Split(string(raw), ".")
	if len(parts) != 3 {
		t.Fatalf("expected a compact JWS, got %s", raw)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode the payload: %v", err)
	}
	return decodeExactly(t, payload).(map[string]any)
}

func expectPublishedAsEncodingJSON(t *testing.T, where string, published map[string]any) {
	t.Helper()
	for parameter, value := range publishedGoValues() {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("failed to marshal the fixture: %v", err)
		}
		want := decodeExactly(t, raw)
		if got := published[parameter]; !reflect.DeepEqual(got, want) {
			t.Errorf("expected %s to publish %s as encoding/json writes it, %s, got %#v", where, parameter, raw, got)
		}
	}
}

func TestServer_PublishesAGoTypedValueAsEncodingJSONWritesIt(t *testing.T) {
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build the signer: %v", err)
	}
	federation := model.FederationMetadata{}
	relyingParty := model.OpenIDRelyingPartyMetadata{}
	pinned := map[string]model.PolicyOperators{}
	for parameter, value := range publishedGoValues() {
		federation[parameter] = value
		relyingParty[parameter] = value
		operator, err := model.NewValue(value)
		if err != nil {
			t.Fatalf("expected the value operator to build, got %v", err)
		}
		pinned[parameter] = model.PolicyOperators{Metadata: []model.MetadataPolicyOperator{*operator}}
	}
	subordinate := leafSubordinate(t)
	subordinate.Metadata = &model.Metadata{OpenIDRelyingPartyMetadata: &relyingParty}
	subordinate.Policies = model.MetadataPolicy{OpenIDRelyingPartyMetadata: pinned}
	intermediate := &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Hour}
	intermediate.AddSubordinate("https://leaf.example.com", subordinate)

	server := mustNewServer(t, model.ServerConfiguration{
		EntityIdentifier:            "https://ta.example.com",
		SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "ta"},
		EntityConfiguration:         model.EntityStatement{Iss: "https://ta.example.com", Metadata: &model.Metadata{FederationMetadata: &federation}},
		EntityConfigurationLifetime: time.Hour,
		IntermediateConfiguration:   intermediate,
	})
	mux := http.NewServeMux()
	server.Configure(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	configuration := publishedClaims(t, ts, "/.well-known/openid-federation")
	expectPublishedAsEncodingJSON(t, "the entity configuration", configuration["metadata"].(map[string]any)["federation_entity"].(map[string]any))

	statement := publishedClaims(t, ts, "/fetch?sub="+url.QueryEscape("https://leaf.example.com"))
	expectPublishedAsEncodingJSON(t, "the subordinate statement's metadata", statement["metadata"].(map[string]any)["openid_relying_party"].(map[string]any))
	operands := map[string]any{}
	for parameter, operators := range statement["metadata_policy"].(map[string]any)["openid_relying_party"].(map[string]any) {
		operands[parameter] = operators.(map[string]any)["value"]
	}
	expectPublishedAsEncodingJSON(t, "the subordinate statement's value operands", operands)
}
