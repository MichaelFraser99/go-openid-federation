package entityid

import (
	"reflect"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestUnlistedSuperiorFaults_NamesEachMalformedEntry(t *testing.T) {
	const wallet, anchor, intermediate = "https://wallet.example", "https://ta.example", "https://im.example"

	tests := []struct {
		name       string
		configured map[model.EntityIdentifier][]model.EntityIdentifier
		faults     []string
	}{
		{name: "nothing configured"},
		{name: "an empty map", configured: map[model.EntityIdentifier][]model.EntityIdentifier{}},
		{name: "one superior", configured: map[model.EntityIdentifier][]model.EntityIdentifier{wallet: {anchor}}},
		{name: "several superiors", configured: map[model.EntityIdentifier][]model.EntityIdentifier{wallet: {intermediate, anchor}}},
		{name: "a superior configured twice", configured: map[model.EntityIdentifier][]model.EntityIdentifier{wallet: {anchor, anchor}}},
		{
			name:       "an entity that is not an entity identifier",
			configured: map[model.EntityIdentifier][]model.EntityIdentifier{"http://wallet.example": {anchor}},
			faults:     []string{`Experimental.UnlistedSuperiors["http://wallet.example"] is not an entity identifier: `},
		},
		{
			name:       "an entity with an empty list",
			configured: map[model.EntityIdentifier][]model.EntityIdentifier{wallet: {}},
			faults:     []string{`Experimental.UnlistedSuperiors["https://wallet.example"] lists no superior`},
		},
		{
			name:       "an entity with a nil list",
			configured: map[model.EntityIdentifier][]model.EntityIdentifier{wallet: nil},
			faults:     []string{`Experimental.UnlistedSuperiors["https://wallet.example"] lists no superior`},
		},
		{
			name:       "a superior that is not an entity identifier",
			configured: map[model.EntityIdentifier][]model.EntityIdentifier{wallet: {anchor, "ta.example"}},
			faults:     []string{`Experimental.UnlistedSuperiors["https://wallet.example"][1] is not an entity identifier: `},
		},
		{
			name:       "a superior that is the entity itself",
			configured: map[model.EntityIdentifier][]model.EntityIdentifier{wallet: {wallet}},
			faults:     []string{`Experimental.UnlistedSuperiors["https://wallet.example"][0] names the entity itself`},
		},
		{
			name:       "a superior that is the entity itself spelled another way",
			configured: map[model.EntityIdentifier][]model.EntityIdentifier{wallet: {anchor, "https://WALLET.example:443/"}},
			faults:     []string{`Experimental.UnlistedSuperiors["https://wallet.example"][1] names the entity itself`},
		},
		{
			name: "every fault, in entity order",
			configured: map[model.EntityIdentifier][]model.EntityIdentifier{
				"https://z.example": {},
				"https://a.example": {"https://a.example", "nope"},
				"nope":              {anchor},
			},
			faults: []string{
				`Experimental.UnlistedSuperiors["https://a.example"][0] names the entity itself`,
				`Experimental.UnlistedSuperiors["https://a.example"][1] is not an entity identifier: `,
				`Experimental.UnlistedSuperiors["https://z.example"] lists no superior`,
				`Experimental.UnlistedSuperiors["nope"] is not an entity identifier: `,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			faults := UnlistedSuperiorFaults(tc.configured)
			var got []string
			for i, fault := range faults {
				text := fault.Error()
				if i < len(tc.faults) && strings.HasSuffix(tc.faults[i], ": ") && strings.HasPrefix(text, tc.faults[i]) {
					text = tc.faults[i]
				}
				got = append(got, text)
			}
			if !reflect.DeepEqual(got, tc.faults) {
				t.Errorf("expected %q, got %q", tc.faults, got)
			}
		})
	}
}

func TestUnlistedSuperiorFaults_BoundsTheIdentifierItQuotes(t *testing.T) {
	long := model.EntityIdentifier("https://wallet.example/" + strings.Repeat("a", 4096) + "TAIL")
	faults := UnlistedSuperiorFaults(map[model.EntityIdentifier][]model.EntityIdentifier{long: {}})
	if len(faults) != 1 {
		t.Fatalf("expected one fault, got %v", faults)
	}
	if text := faults[0].Error(); strings.Contains(text, "TAIL") || !strings.Contains(text, "lists no superior") {
		t.Errorf("expected the quoted identifier cut short, got %d bytes", len(text))
	}
}

func TestUnlistedSuperiorFaults_JudgesALongEntityByItsWholeIdentifier(t *testing.T) {
	long := model.EntityIdentifier("https://wallet.example/" + strings.Repeat("a", 4096))
	if faults := UnlistedSuperiorFaults(map[model.EntityIdentifier][]model.EntityIdentifier{long: {"https://ta.example"}}); len(faults) != 0 {
		t.Errorf("expected a long entity with a superior to be accepted, got %v", faults)
	}
}
