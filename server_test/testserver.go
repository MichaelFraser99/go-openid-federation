package server_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
)

// TestServer creates a local federation for testing purposes.
func TestServer(t *testing.T) *httptest.Server {
	var testServerURL string

	leafSigner, err := jws.GetSigner(josemodel.ES256, nil)
	if err != nil {
		t.Fatalf("expected no error creating leaf signer, got %q", err.Error())
	}
	leafJWK, err := jwk.PublicJwk(leafSigner.Public())
	if err != nil {
		t.Fatalf("expected no error creating leaf JWK, got %q", err.Error())
	}
	leafJWKBytes, err := json.Marshal(leafJWK)
	if err != nil {
		t.Fatalf("expected no error creating leaf JWK bytes, got %q", err.Error())
	}

	intermediateSigner1, err := jws.GetSigner(josemodel.ES256, nil)
	if err != nil {
		t.Fatalf("expected no error creating intermediate signer 1, got %q", err.Error())
	}
	intermediateJWK, err := jwk.PublicJwk(intermediateSigner1.Public())
	if err != nil {
		t.Fatalf("expected no error creating intermediate JWK, got %q", err.Error())
	}
	intermediateJWKBytes, err := json.Marshal(intermediateJWK)
	if err != nil {
		t.Fatalf("expected no error creating intermediate JWK bytes, got %q", err.Error())
	}
	intermediateSigner2, err := jws.GetSigner(josemodel.ES256, nil)
	if err != nil {
		t.Fatalf("expected no error creating intermediate signer 2, got %q", err.Error())
	}
	intermediateJWK2, err := jwk.PublicJwk(intermediateSigner2.Public())
	if err != nil {
		t.Fatalf("expected no error creating intermediate JWK, got %q", err.Error())
	}
	intermediateJWK2Bytes, err := json.Marshal(intermediateJWK2)
	if err != nil {
		t.Fatalf("expected no error creating intermediate JWK bytes, got %q", err.Error())
	}
	trustAnchorSigner, err := jws.GetSigner(josemodel.ES256, nil)
	if err != nil {
		t.Fatalf("expected no error creating trust anchor signer, got %q", err.Error())
	}
	trustAnchorJWK, err := jwk.PublicJwk(trustAnchorSigner.Public())
	if err != nil {
		t.Fatalf("expected no error creating trust anchor JWK, got %q", err.Error())
	}
	trustAnchorJWKBytes, err := json.Marshal(trustAnchorJWK)
	if err != nil {
		t.Fatalf("expected no error creating trust anchor JWK bytes, got %q", err.Error())
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/leaf/.well-known/openid-federation", func(w http.ResponseWriter, r *http.Request) {

		leafEC := fmt.Sprintf(`{
  "authority_hints": [
    "%s/int1"
  ],
  "exp": %d,
  "iat": %d,
  "iss": "%s/leaf",
  "sub": "%s/leaf",
  "jwks": {
    "keys": [%s]
  },
  "metadata": {
    "openid_provider": {
      "issuer": "https://op.umu.se/openid",
      "signed_jwks_uri": "https://op.umu.se/openid/jwks.jose",
      "authorization_endpoint":
        "https://op.umu.se/openid/authorization",
      "client_registration_types_supported": [
        "automatic",
        "explicit"
      ],
      "request_parameter_supported": true,
      "grant_types_supported": [
        "authorization_code",
        "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer"
      ],
      "id_token_signing_alg_values_supported": [
        "ES256", "RS256"
      ],
      "logo_uri":
        "https://www.umu.se/img/umu-logo-left-neg-SE.svg",
      "op_policy_uri":
        "https://www.umu.se/en/website/legal-information/",
      "response_types_supported": [
        "code",
        "code id_token",
        "token"
      ],
      "subject_types_supported": [
        "pairwise",
        "public"
      ],
      "token_endpoint": "https://op.umu.se/openid/token",
      "federation_registration_endpoint":
        "https://op.umu.se/openid/fedreg",
      "token_endpoint_auth_methods_supported": [
        "client_secret_post",
        "client_secret_basic",
        "client_secret_jwt",
        "private_key_jwt"
      ]
    }
  }
}`, testServerURL, time.Now().Add(10*time.Minute).UTC().Unix(), time.Now().UTC().Unix(), testServerURL, testServerURL, string(leafJWKBytes))
		var esMap map[string]any
		err := json.Unmarshal([]byte(leafEC), &esMap)
		if err != nil {
			t.Fatalf("expected no error unmarshalling trust anchor int1 ss, got %q", err.Error())
		}
		signed, err := jwt.New(leafSigner, map[string]any{
			"kid": (*leafJWK)["kid"],
			"typ": "entity-statement+jwt",
		}, esMap, jwt.Opts{Algorithm: josemodel.ES256})
		if err != nil {
			t.Fatalf("expected no error signing ta, got %q", err.Error())
		}
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		_, _ = w.Write([]byte(*signed))
	})
	mux.HandleFunc("/int1/.well-known/openid-federation", func(w http.ResponseWriter, r *http.Request) {
		int1EC := fmt.Sprintf(`{
  "authority_hints": [
    "%s/int2"
  ],
  "exp": %d,
  "iat": %d,
  "iss": "%s/int1",
  "sub": "%s/int1",
  "jwks": {
    "keys": [%s]
  },
  "metadata": {
    "federation_entity": {
      "contacts": ["ops@umu.se"],
      "federation_fetch_endpoint": "%s/int1/fetch",
      "homepage_uri": "https://www.umu.se",
      "organization_name": "UmU"
    }
  }
}`, testServerURL, time.Now().Add(10*time.Minute).UTC().Unix(), time.Now().UTC().Unix(), testServerURL, testServerURL, string(intermediateJWKBytes), testServerURL)
		var esMap map[string]any
		err := json.Unmarshal([]byte(int1EC), &esMap)
		if err != nil {
			t.Fatalf("expected no error unmarshalling trust anchor int1 ss, got %q", err.Error())
		}
		signed, err := jwt.New(intermediateSigner1, map[string]any{
			"kid": (*intermediateJWK)["kid"],
			"typ": "entity-statement+jwt",
		}, esMap, jwt.Opts{Algorithm: josemodel.ES256})
		if err != nil {
			t.Fatalf("expected no error signing ta, got %q", err.Error())
		}
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		_, _ = w.Write([]byte(*signed))
	})
	mux.HandleFunc("/int1/fetch", func(w http.ResponseWriter, r *http.Request) {
		int1LeafSS := fmt.Sprintf(`{
  "exp": %d,
  "iat": %d,
  "iss": "%s/int1",
  "sub": "%s/leaf",
  "source_endpoint": "https://umu.se/oidc/fedapi",
  "jwks": {
    "keys": [%s]
  },
  "metadata_policy": {
    "openid_provider": {
      "contacts": {
        "add": [
          "ops@swamid.se"
        ]
      },
      "organization_name": {
        "value": "University of Umeå"
      },
      "subject_types_supported": {
        "value": [
          "pairwise"
        ]
      },
      "token_endpoint_auth_methods_supported": {
        "default": [
          "private_key_jwt"
        ],
        "subset_of": [
          "private_key_jwt",
          "client_secret_jwt"
        ],
        "superset_of": [
          "private_key_jwt"
        ]
      }
    }
  }
}`, time.Now().Add(5*time.Minute).UTC().Unix(), time.Now().UTC().Unix(), testServerURL, testServerURL, string(leafJWKBytes))
		var esMap map[string]any
		err := json.Unmarshal([]byte(int1LeafSS), &esMap)
		if err != nil {
			t.Fatalf("expected no error unmarshalling int1 to leaf ss, got %q", err.Error())
		}
		signed, err := jwt.New(intermediateSigner1, map[string]any{
			"kid": (*intermediateJWK)["kid"],
			"typ": "entity-statement+jwt",
		}, esMap, jwt.Opts{Algorithm: josemodel.ES256})
		if err != nil {
			t.Fatalf("expected no error signing ta, got %q", err.Error())
		}
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		_, _ = w.Write([]byte(*signed))
	})
	mux.HandleFunc("/int2/.well-known/openid-federation", func(w http.ResponseWriter, r *http.Request) {
		int2EC := fmt.Sprintf(`{
  "authority_hints": [
    "%s/ta"
  ],
  "exp": %d,
  "iat": %d,
  "iss": "%s/int2",
  "sub": "%s/int2",
  "jwks": {
    "keys": [%s]
  },
  "metadata": {
    "federation_entity": {
      "contacts": ["ops@swamid.se"],
      "federation_fetch_endpoint":
        "%s/int2/fetch",
      "homepage_uri": "https://www.sunet.se/swamid/",
      "organization_name": "SWAMID"
    }
  }
}`, testServerURL, time.Now().Add(10*time.Minute).UTC().Unix(), time.Now().UTC().Unix(), testServerURL, testServerURL, string(intermediateJWK2Bytes), testServerURL)
		var esMap map[string]any
		err := json.Unmarshal([]byte(int2EC), &esMap)
		if err != nil {
			t.Fatalf("expected no error unmarshalling int2 ec, got %q", err.Error())
		}
		signed, err := jwt.New(intermediateSigner2, map[string]any{
			"kid": (*intermediateJWK2)["kid"],
			"typ": "entity-statement+jwt",
		}, esMap, jwt.Opts{Algorithm: josemodel.ES256})
		if err != nil {
			t.Fatalf("expected no error signing ta, got %q", err.Error())
		}
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		_, _ = w.Write([]byte(*signed))
	})
	mux.HandleFunc("/int2/fetch", func(w http.ResponseWriter, r *http.Request) {
		int2Int1SS := fmt.Sprintf(`{
  "exp": %d,
  "iat": %d,
  "iss": "%s/int2",
  "sub": "%s/int1",
  "source_endpoint": "https://swamid.se/fedapi",
  "jwks": {
    "keys": [%s]
  },
  "metadata_policy": {
    "openid_provider": {
      "id_token_signing_alg_values_supported": {
        "subset_of": [
          "RS256",
          "ES256",
          "ES384",
          "ES512"
        ]
      },
      "token_endpoint_auth_methods_supported": {
        "subset_of": [
          "client_secret_jwt",
          "private_key_jwt"
        ]
      },
      "userinfo_signing_alg_values_supported": {
        "subset_of": [
          "ES256",
          "ES384",
          "ES512"
        ]
      }
    }
  }
}`, time.Now().Add(10*time.Minute).UTC().Unix(), time.Now().UTC().Unix(), testServerURL, testServerURL, string(intermediateJWKBytes))
		var esMap map[string]any
		err := json.Unmarshal([]byte(int2Int1SS), &esMap)
		if err != nil {
			t.Fatalf("expected no error unmarshalling int2 to int1 ss, got %q", err.Error())
		}
		signed, err := jwt.New(intermediateSigner2, map[string]any{
			"kid": (*intermediateJWK2)["kid"],
			"typ": "entity-statement+jwt",
		}, esMap, jwt.Opts{Algorithm: josemodel.ES256})
		if err != nil {
			t.Fatalf("expected no error signing ta, got %q", err.Error())
		}
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		_, _ = w.Write([]byte(*signed))
	})
	mux.HandleFunc("/ta/.well-known/openid-federation", func(w http.ResponseWriter, r *http.Request) {
		trustAnchorEC := fmt.Sprintf(`{
  "exp": %d,
  "iat": %d,
  "iss": "%s/ta",
  "sub": "%s/ta",
  "jwks": {
    "keys": [%s]
  },
  "metadata": {
    "federation_entity": {
      "federation_fetch_endpoint": "%s/ta/fetch"
    }
  }
}`, time.Now().Add(10*time.Minute).UTC().Unix(), time.Now().UTC().Unix(), testServerURL, testServerURL, string(trustAnchorJWKBytes), testServerURL)
		var esMap map[string]any
		err := json.Unmarshal([]byte(trustAnchorEC), &esMap)
		if err != nil {
			t.Fatalf("expected no error unmarshalling trust anchor ec, got %q", err.Error())
		}
		signed, err := jwt.New(trustAnchorSigner, map[string]any{
			"kid": (*trustAnchorJWK)["kid"],
			"typ": "entity-statement+jwt",
		}, esMap, jwt.Opts{Algorithm: josemodel.ES256})
		if err != nil {
			t.Fatalf("expected no error signing ta, got %q", err.Error())
		}
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		_, _ = w.Write([]byte(*signed))
	})
	mux.HandleFunc("/ta/fetch", func(w http.ResponseWriter, r *http.Request) {
		trustAnchorInt2SS := fmt.Sprintf(`{
  "exp": %d,
  "iat": %d,
  "iss": "%s/ta",
  "sub": "%s/int2",
  "source_endpoint": "https://edugain.geant.org/edugain/api",
  "jwks": {
    "keys": [%s]
  },
  "metadata_policy": {
    "openid_provider": {
      "contacts": {
        "add": ["ops@edugain.geant.org"]
      }
    },
    "openid_relying_party": {
      "contacts": {
        "add": ["ops@edugain.geant.org"]
      }
    }
  }
}`, time.Now().Add(10*time.Minute).UTC().Unix(), time.Now().UTC().Unix(), testServerURL, testServerURL, string(intermediateJWK2Bytes))
		var esMap map[string]any
		err := json.Unmarshal([]byte(trustAnchorInt2SS), &esMap)
		if err != nil {
			t.Fatalf("expected no error unmarshalling trust anchor to int2 ss, got %q", err.Error())
		}
		signed, err := jwt.New(trustAnchorSigner, map[string]any{
			"kid": (*trustAnchorJWK)["kid"],
			"typ": "entity-statement+jwt",
		}, esMap, jwt.Opts{Algorithm: josemodel.ES256})
		if err != nil {
			t.Fatalf("expected no error signing ta aa, got %q", err.Error())
		}
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		_, _ = w.Write([]byte(*signed))
	})

	s := httptest.NewTLSServer(mux)
	testServerURL = s.URL
	return s
}
