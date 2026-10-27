package resolvecache

import (
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestRecordDeadEnd_StopsHoldingTheConfigurationItWillNeverReadAgain(t *testing.T) {
	dead := model.EntityIdentifier("https://dead.example.com")
	live := model.EntityIdentifier("https://live.example.com")
	target := model.EntityIdentifier("https://ta.example.com")

	tests := map[string]struct {
		recorded  DeadEnd
		stillHeld map[model.EntityIdentifier]bool
	}{
		"the subject recorded is dropped and others are kept": {
			recorded:  DeadEnd{Subject: dead, Target: target},
			stillHeld: map[model.EntityIdentifier]bool{dead: false, live: true},
		},
		"a subject never recorded is kept": {
			recorded:  DeadEnd{Subject: "https://other.example.com", Target: target},
			stillHeld: map[model.EntityIdentifier]bool{dead: true, live: true},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cache := New()
			for _, subject := range []model.EntityIdentifier{dead, live} {
				signed := string(subject)
				cache.Store(subject, &signed, &model.EntityStatement{Iss: subject, Sub: subject})
			}

			cache.RecordDeadEnd(test.recorded)

			for subject, want := range test.stillHeld {
				if _, _, held := cache.Load(subject); held != want {
					t.Errorf("expected %s held=%t, got %t", subject, want, held)
				}
			}
			if !cache.IsDeadEnd(test.recorded) {
				t.Error("expected the dead end to stay remembered after its configuration is dropped")
			}
		})
	}
}

func TestRecordDeadEnd_TheBytesAlreadyChargedAreNotRefunded(t *testing.T) {
	cache := New()
	subject := model.EntityIdentifier("https://dead.example.com")
	signed := "signed"
	cache.Store(subject, &signed, &model.EntityStatement{})
	cache.RecordPeerBytes(1024)

	cache.RecordDeadEnd(DeadEnd{Subject: subject, Target: "https://ta.example.com"})

	if got := cache.PeerBytes(); got != 1024 {
		t.Errorf("expected the 1024 bytes already charged to stand, got %d", got)
	}
}
