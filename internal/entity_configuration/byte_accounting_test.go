package entity_configuration

import (
	"errors"
	"fmt"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
	"github.com/MichaelFraser99/go-openid-federation/server_test"
)

func TestRetrieve_ChargesWhatTheRequestHoldsAndChargesItOnce(t *testing.T) {
	testServer := server_test.TestServer(t)
	identifier := model.EntityIdentifier(fmt.Sprintf("%s/leaf", testServer.URL))
	cfg := model.Configuration{HttpClient: testServer.Client()}
	cache := resolvecache.New()

	signed, statement, err := Retrieve(t.Context(), cfg, identifier, cache)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := 2*int64(len(*signed)) + int64(statement.DecodedValues())*model.DecodedValueCost
	if got := cache.PeerBytes(); got != want {
		t.Fatalf("[8.2] a statement is charged the signed text and its parsed form together, so %d was expected, got %d", want, got)
	}
	if statement.DecodedValues() == 0 {
		t.Fatal("a parsed statement decoded to no values, so the parsed half of the charge is not being counted")
	}
	if want <= int64(len(*signed)) {
		t.Errorf("the charge must exceed the signed length, since the parsed form is retained too: %d against %d signed bytes", want, len(*signed))
	}

	for range 3 {
		if _, _, err := Retrieve(t.Context(), cfg, identifier, cache); err != nil {
			t.Fatalf("unexpected error on a cache hit: %v", err)
		}
	}
	if got := cache.PeerBytes(); got != want {
		t.Errorf("[8.2] a cache hit holds nothing new, so it must charge nothing: expected %d, got %d", want, got)
	}
}

func TestRetrieve_ABudgetExactlySpentStillAllowsTheNextFetch(t *testing.T) {
	testServer := server_test.TestServer(t)
	cache := resolvecache.New()

	if _, _, err := Retrieve(t.Context(), model.Configuration{HttpClient: testServer.Client()}, model.EntityIdentifier(fmt.Sprintf("%s/leaf", testServer.URL)), cache); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	spent := cache.PeerBytes()
	if spent == 0 {
		t.Fatal("the first fetch charged nothing, so this test asserts nothing")
	}

	cfg := model.Configuration{HttpClient: testServer.Client(), MaxRequestPeerBytes: spent}

	if _, _, err := Retrieve(t.Context(), cfg, model.EntityIdentifier(fmt.Sprintf("%s/int1", testServer.URL)), cache); err != nil {
		t.Fatalf("[8.2] a budget held exactly, not exceeded, must still allow the next fetch, got %v", err)
	}
	if _, _, err := Retrieve(t.Context(), cfg, model.EntityIdentifier(fmt.Sprintf("%s/int2", testServer.URL)), cache); !errors.Is(err, model.ErrLimitReached) {
		t.Errorf("[8.2] a budget exceeded must refuse the next fetch as a limit, got %v", err)
	}
}

func TestRetrieve_AStatementThatFailsValidationIsNeitherChargedNorHeld(t *testing.T) {
	testServer := server_test.TestServer(t)
	cfg := model.Configuration{HttpClient: testServer.Client()}
	cache := resolvecache.New()

	if _, _, err := Retrieve(t.Context(), cfg, model.EntityIdentifier(fmt.Sprintf("%s/does-not-exist", testServer.URL)), cache); err == nil {
		t.Fatal("expected a statement that cannot be retrieved to fail")
	}
	if got := cache.PeerBytes(); got != 0 {
		t.Errorf("[8.2] nothing was retained, so nothing may be charged, got %d", got)
	}
}

func TestRetrieve_TheChargeCountsBothHalvesIndependently(t *testing.T) {
	testServer := server_test.TestServer(t)
	cfg := model.Configuration{HttpClient: testServer.Client()}
	cache := resolvecache.New()

	signed, statement, err := Retrieve(t.Context(), cfg, model.EntityIdentifier(fmt.Sprintf("%s/leaf", testServer.URL)), cache)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	charged := cache.PeerBytes()
	signedHalf := 2 * int64(len(*signed))
	parsedHalf := int64(statement.DecodedValues()) * model.DecodedValueCost

	if parsedHalf == 0 {
		t.Fatal("the parsed half is zero, so this test cannot tell whether it is counted")
	}
	if charged < signedHalf {
		t.Errorf("[8.2] the signed text is retained twice, as itself and as the strings the parsed form holds, so at least %d must be charged, got %d", signedHalf, charged)
	}
	if charged < parsedHalf {
		t.Errorf("[8.2] the parsed form is retained, so at least %d must be charged for its %d values, got %d", parsedHalf, statement.DecodedValues(), charged)
	}
	if charged != signedHalf+parsedHalf {
		t.Errorf("[8.2] both halves are retained, so both must be charged: expected %d + %d = %d, got %d", signedHalf, parsedHalf, signedHalf+parsedHalf, charged)
	}
}
