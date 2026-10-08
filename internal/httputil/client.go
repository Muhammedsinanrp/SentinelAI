package httputil

import (
	"net/http"
	"net/url"
	"time"

	"golang.org/x/time/rate"
)

// Client is an HTTP client with rate limiting and optional proxy support.
type Client struct {
	HTTP *http.Client
	Lim  *rate.Limiter
}

func New(rps float64, burst int, proxyURL string) (*Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if proxyURL != "" {
		p, err := parseProxy(proxyURL)
		if err != nil {
			return nil, err
		}
		transport.Proxy = http.ProxyURL(p)
	}
	if burst <= 0 {
		burst = 1
	}
	return &Client{
		HTTP: &http.Client{
			Timeout:   15 * time.Second,
			Transport: transport,
		},
		Lim: rate.NewLimiter(rate.Limit(rps), burst),
	}, nil
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	if err := c.Lim.Wait(ctx); err != nil {
		return nil, err
	}
	return c.HTTP.Do(req)
}

func parseProxy(raw string) (*url.URL, error) {
	return url.Parse(raw)
}
