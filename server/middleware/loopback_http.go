package middleware

import (
	"net"
	"net/http"
	"strings"
)

// ListenAndServeHTTPRedirect answers every plain HTTP request with a redirect
// to the HTTPS port.
func ListenAndServeHTTPRedirect(httpAddr string, httpsPort string) error {
	return http.ListenAndServe(httpAddr, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "https://"+redirectHost(req.Host, httpsPort)+req.URL.RequestURI(), http.StatusTemporaryRedirect)
	}))
}

func redirectHost(requestHost string, httpsPort string) string {
	host := requestHost
	if h, _, err := net.SplitHostPort(requestHost); err == nil {
		host = h
	} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	}

	if httpsPort != "443" {
		return net.JoinHostPort(host, httpsPort)
	}

	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") && !strings.HasSuffix(host, "]") {
		return "[" + host + "]"
	}

	return host
}
