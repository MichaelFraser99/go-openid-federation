package peerclient

import (
	"errors"
	"net/http"
)

const maxRedirects = 10

var ErrRedirectOffHTTPS = errors.New("refused a redirect to a url that does not use https")

func HTTPSOnly(client *http.Client) *http.Client {
	restricted := *client
	followed := client.CheckRedirect
	restricted.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if request.URL.Scheme != "https" {
			return ErrRedirectOffHTTPS
		}
		if followed != nil {
			return followed(request, via)
		}
		if len(via) >= maxRedirects {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	return &restricted
}
