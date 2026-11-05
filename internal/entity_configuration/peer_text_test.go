package entity_configuration

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type failingBody struct{ err error }

func (b failingBody) Read([]byte) (int, error) { return 0, b.err }

func (b failingBody) Close() error { return nil }

type failingBodyTransport struct{ err error }

func (f failingBodyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": []string{"application/entity-statement+jwt"}},
		Body:       failingBody(f),
		Request:    request,
	}, nil
}

func TestRetrieve_ABodyThatCannotBeReadIsDescribedWithoutTheReadersText(t *testing.T) {
	const marker = "peer-chosen-5Rt"
	client := &http.Client{Transport: failingBodyTransport{err: errors.New("connection reset by " + marker)}}

	_, _, err := Retrieve(t.Context(), model.Configuration{HttpClient: client}, "https://leaf.example.com", resolvecache.New())
	if err == nil {
		t.Fatal("expected the response to be refused")
	}
	if strings.Contains(err.Error(), marker) {
		t.Errorf("[8.9] the read error's text must not reach the error, got %q", err.Error())
	}
	if err.Error() != "failed to read the entity configuration response body" {
		t.Errorf("expected the fixed description, got %q", err.Error())
	}
}

func TestRetrieve_ARefusedResponseIsDescribedWithoutThePeersText(t *testing.T) {
	const marker = "peer-chosen-3Vw"

	tests := []struct {
		name        string
		handler     http.HandlerFunc
		description string
	}{
		{
			name: "a status line with a reason phrase the peer wrote",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				connection, buffered, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Errorf("failed to take over the connection: %v", err)
					return
				}
				defer connection.Close() //nolint:errcheck
				_, _ = buffered.WriteString("HTTP/1.1 418 " + marker + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
				_ = buffered.Flush()
			},
			description: "non-200 response from the entity configuration endpoint",
		},
		{
			name: "a content type the peer chose",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/"+marker)
				_, _ = w.Write([]byte("not-a-jwt"))
			},
			description: "invalid Content-Type from the entity configuration endpoint",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewTLSServer(tc.handler)
			defer s.Close()

			_, _, err := Retrieve(t.Context(), model.Configuration{HttpClient: s.Client()}, model.EntityIdentifier(s.URL), resolvecache.New())
			if err == nil {
				t.Fatal("expected the response to be refused")
			}
			if strings.Contains(err.Error(), marker) {
				t.Errorf("[8.9] text a peer chose must not reach the error, got %q", err.Error())
			}
			if err.Error() != tc.description {
				t.Errorf("expected %q, got %q", tc.description, err.Error())
			}
		})
	}
}
