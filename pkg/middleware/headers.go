package middleware

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/setting"
	macaron "gopkg.in/macaron.v1"
)

const HeaderNameNoBackendCache = "X-Grafana-NoCache"

func HandleNoCacheHeader() macaron.Handler {
	return func(ctx *models.ReqContext) {
		ctx.SkipCache = ctx.Req.Header.Get(HeaderNameNoBackendCache) == "true"
	}
}

func AddSecureResponseHeaders(cfg *setting.Cfg) macaron.Handler {
	return func(res http.ResponseWriter, req *http.Request, c *macaron.Context) {
		forceSTSHdr := (cfg.Protocol == setting.HTTPSScheme || cfg.Protocol == setting.HTTP2Scheme) && cfg.StrictTransportSecurity
		secureOptions := secureOptions{
			ContentTypeNosniff:    cfg.ContentTypeProtectionHeader,
			BrowserXssFilter:      cfg.XSSProtectionHeader,
			FrameDeny:             !cfg.AllowEmbedding,
			ForceSTSHeader:        forceSTSHdr,
			ContentSecurityPolicy: cfg.ContentSecurityPolicy,
		}
		if forceSTSHdr {
			secureOptions.STSSeconds = int64(cfg.StrictTransportSecurityMaxAge)
			secureOptions.STSPreload = setting.StrictTransportSecurityPreload
			secureOptions.STSIncludeSubdomains = cfg.StrictTransportSecuritySubDomains
		}
		secureMiddleware := New(secureOptions)

		nonce, err := secureMiddleware.ProcessAndReturnNonce(res, req)

		if err != nil {
			return
		}

		ctx, ok := c.Data["ctx"].(*models.ReqContext)
		if !ok {
			return
		}

		ctx.RequestNonce = nonce
	}
}

func New(options ...Options) *Secure {
	var o Options
	if len(options) == 0 {
		o = Options{}
	} else {
		o = options[0]
	}

	o.ContentSecurityPolicy = strings.Replace(o.ContentSecurityPolicy, "$NONCE", "'nonce-%[1]s'", -1)
	o.ContentSecurityPolicyReportOnly = strings.Replace(o.ContentSecurityPolicyReportOnly, "$NONCE", "'nonce-%[1]s'", -1)

	o.nonceEnabled = strings.Contains(o.ContentSecurityPolicy, "%[1]s") || strings.Contains(o.ContentSecurityPolicyReportOnly, "%[1]s")

	s := &Secure{
		opt:            o,
		badHostHandler: http.HandlerFunc(defaultBadHostHandler),
	}

	if s.opt.AllowedHostsAreRegex {
		// Test for invalid regular expressions in AllowedHosts
		for _, allowedHost := range o.AllowedHosts {
			regex, err := regexp.Compile(fmt.Sprintf("^%s$", allowedHost))
			if err != nil {
				panic(fmt.Sprintf("Error parsing AllowedHost: %s", err))
			}
			s.cRegexAllowedHosts = append(s.cRegexAllowedHosts, regex)
		}
	}

	s.ctxSecureHeaderKey = ctxDefaultSecureHeaderKey
	if len(s.opt.SecureContextKey) > 0 {
		s.ctxSecureHeaderKey = secureCtxKey(s.opt.SecureContextKey)
	}

	return s
}

// ProcessAndReturnNonce runs the actual checks and writes the headers in the ResponseWriter.
// In addition, the generated nonce for the request is returned as well as the error value.
func (s *Secure) ProcessAndReturnNonce(w http.ResponseWriter, r *http.Request) (string, error) {
	responseHeader, newR, err := s.processRequest(w, r)
	if err != nil {
		return "", err
	}

	addResponseHeaders(responseHeader, w)

	return CSPNonce(newR.Context()), err
}

// addResponseHeaders Adds the headers from 'responseHeader' to the response.
func addResponseHeaders(responseHeader http.Header, w http.ResponseWriter) {
	for key, values := range responseHeader {
		for _, value := range values {
			w.Header().Set(key, value)
		}
	}
}

const cspNonceKey key = iota

// CSPNonce returns the nonce value associated with the present request. If no nonce has been generated it returns an empty string.
func CSPNonce(c context.Context) string {
	if val, ok := c.Value(cspNonceKey).(string); ok {
		return val
	}

	return ""
}

type secureOptions struct {
	// If BrowserXssFilter is true, adds the X-XSS-Protection header with the value `1; mode=block`. Default is false.
	BrowserXssFilter bool // nolint: golint
	// If ContentTypeNosniff is true, adds the X-Content-Type-Options header with the value `nosniff`. Default is false.
	ContentTypeNosniff bool
	// If ForceSTSHeader is set to true, the STS header will be added even when the connection is HTTP. Default is false.
	ForceSTSHeader bool
	// If FrameDeny is set to true, adds the X-Frame-Options header with the value of `DENY`. Default is false.
	FrameDeny bool
	// When developing, the AllowedHosts, SSL, and STS options can cause some unwanted effects. Usually testing happens on http, not https, and on localhost, not your production domain... so set this to true for dev environment.
	// If you would like your development environment to mimic production with complete Host blocking, SSL redirects, and STS headers, leave this as false. Default if false.
	IsDevelopment bool
	// nonceEnabled is used internally for dynamic nouces.
	nonceEnabled bool
	// If SSLRedirect is set to true, then only allow https requests. Default is false.
	SSLRedirect bool
	// If SSLForceHost is true and SSLHost is set, requests will be forced to use SSLHost even the ones that are already using SSL. Default is false.
	SSLForceHost bool
	// If SSLTemporaryRedirect is true, the a 302 will be used while redirecting. Default is false (301).
	SSLTemporaryRedirect bool
	// If STSIncludeSubdomains is set to true, the `includeSubdomains` will be appended to the Strict-Transport-Security header. Default is false.
	STSIncludeSubdomains bool
	// If STSPreload is set to true, the `preload` flag will be appended to the Strict-Transport-Security header. Default is false.
	STSPreload bool
	// ContentSecurityPolicy allows the Content-Security-Policy header value to be set with a custom value. Default is "".
	ContentSecurityPolicy string
	// ContentSecurityPolicyReportOnly allows the Content-Security-Policy-Report-Only header value to be set with a custom value. Default is "".
	ContentSecurityPolicyReportOnly string
	// CustomBrowserXssValue allows the X-XSS-Protection header value to be set with a custom value. This overrides the BrowserXssFilter option. Default is "".
	CustomBrowserXssValue string // nolint: golint
	// Passing a template string will replace `$NONCE` with a dynamic nonce value of 16 bytes for each request which can be later retrieved using the Nonce function.
	// Eg: script-src $NONCE -> script-src 'nonce-a2ZobGFoZg=='
	// CustomFrameOptionsValue allows the X-Frame-Options header value to be set with a custom value. This overrides the FrameDeny option. Default is "".
	CustomFrameOptionsValue string
	// PublicKey implements HPKP to prevent MITM attacks with forged certificates. Default is "".
	// Deprecated: This feature is no longer recommended. Though some browsers might still support it, it may have already been removed from the relevant web standards, may be in the process of being dropped, or may only be kept for compatibility purposes. Avoid using it, and update existing code if possible.
	PublicKey string
	// ReferrerPolicy allows sites to control when browsers will pass the Referer header to other sites. Default is "".
	ReferrerPolicy string
	// FeaturePolicy allows to selectively enable and disable use of various browser features and APIs. Default is "".
	FeaturePolicy string
	// SSLHost is the host name that is used to redirect http requests to https. Default is "", which indicates to use the same host.
	SSLHost string
	// AllowedHosts is a list of fully qualified domain names that are allowed. Default is empty list, which allows any and all host names.
	AllowedHosts []string
	// AllowedHostsAreRegex determines, if the provided slice contains valid regular expressions. If this flag is set to true, every request's
	// host will be checked against these expressions. Default is false for backwards compatibility.
	AllowedHostsAreRegex bool
	// HostsProxyHeaders is a set of header keys that may hold a proxied hostname value for the request.
	HostsProxyHeaders []string
	// SSLHostFunc is a function pointer, the return value of the function is the host name that has same functionality as `SSHost`. Default is nil.
	// If SSLHostFunc is nil, the `SSLHost` option will be used.
	SSLHostFunc *SSLHostFunc
	// SSLProxyHeaders is set of header keys with associated values that would indicate a valid https request. Useful when using Nginx: `map[string]string{"X-Forwarded-Proto": "https"}`. Default is blank map.
	SSLProxyHeaders map[string]string
	// STSSeconds is the max-age of the Strict-Transport-Security header. Default is 0, which would NOT include the header.
	STSSeconds int64
	// ExpectCTHeader allows the Expect-CT header value to be set with a custom value. Default is "".
	ExpectCTHeader string
	// SecureContextKey allows a custom key to be specified for context storage.
	SecureContextKey string
}
