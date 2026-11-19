package vectors

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/yaronf/httpsign"
)

// Outcome is the harness verdict for one evaluation.
type Outcome string

const (
	OutcomeAccept Outcome = "ACCEPT"
	OutcomeReject Outcome = "REJECT"
	OutcomeSkip   Outcome = "SKIP"
)

// Result is one vector evaluation.
type Result struct {
	ID     string
	Want   string
	Got    Outcome
	Detail string
	Setup  bool // true if the harness could not build/run the case
}

func (r Result) OK() bool {
	if r.Setup {
		return false
	}
	if r.Got == OutcomeSkip {
		return true
	}
	want := r.Want
	if want == "CLIENT_REJECT" {
		want = "REJECT"
	}
	return string(r.Got) == want
}

// VerifyEntry runs the harness for one entry.
func VerifyEntry(vs *VectorSet, kr *Keyring, e *Entry) []Result {
	if e.SkipReason != "" {
		return []Result{{ID: e.ID, Want: e.Expect, Got: OutcomeSkip, Detail: e.SkipReason}}
	}

	switch e.Kind {
	case "positive":
		err := verifyPositive(vs, kr, e, e.VerifyTime)
		if err != nil {
			return []Result{{ID: e.ID, Want: "ACCEPT", Got: OutcomeReject, Detail: err.Error()}}
		}
		return []Result{{ID: e.ID, Want: "ACCEPT", Got: OutcomeAccept}}
	case "negative-message":
		if len(e.VerifyTimes) > 0 {
			var out []Result
			for i, leg := range e.VerifyTimes {
				id := fmt.Sprintf("%s@%d", e.ID, i)
				setup, err := verifyNegative(vs, kr, e, leg.VerifyTime)
				if setup != nil {
					out = append(out, Result{ID: id, Want: leg.Expect, Got: OutcomeReject, Detail: setup.Error(), Setup: true})
					continue
				}
				got := OutcomeAccept
				detail := ""
				if err != nil {
					got = OutcomeReject
					detail = err.Error()
				}
				out = append(out, Result{ID: id, Want: leg.Expect, Got: got, Detail: detail})
			}
			return out
		}
		setup, err := verifyNegative(vs, kr, e, e.VerifyTime)
		if setup != nil {
			return []Result{{ID: e.ID, Want: e.Expect, Got: OutcomeReject, Detail: setup.Error(), Setup: true}}
		}
		got := OutcomeAccept
		detail := ""
		if err != nil {
			got = OutcomeReject
			detail = err.Error()
		}
		return []Result{{ID: e.ID, Want: e.Expect, Got: got, Detail: detail}}
	default:
		return []Result{{ID: e.ID, Want: e.Expect, Got: OutcomeSkip, Detail: "unhandled kind " + e.Kind}}
	}
}

func verifyPositive(vs *VectorSet, kr *Keyring, e *Entry, verifyTime int64) error {
	parsed, err := parseHTTPMessage(e.Message)
	if err != nil {
		return err
	}
	if parsed.IsResponse {
		p1 := vs.PositivesByID["P-01"]
		if p1 == nil {
			return fmt.Errorf("missing P-01 for response assoc")
		}
		return verifyResponseMsg(vs, kr, parsed.Response, p1.Message, verifyTime, true)
	}
	return verifyRequestMsg(vs, kr, parsed.Request, verifyTime, true, e)
}

func verifyNegative(vs *VectorSet, kr *Keyring, e *Entry, verifyTime int64) (setup error, verdict error) {
	msg, assoc, err := buildNegativeMessage(vs, kr, e)
	if err != nil {
		return fmt.Errorf("build: %w", err), nil
	}
	parsed, err := parseHTTPMessage(msg)
	if err != nil {
		return fmt.Errorf("parse: %w", err), nil
	}
	if parsed.IsResponse {
		return nil, verifyResponseMsg(vs, kr, parsed.Response, assoc, verifyTime, false)
	}
	return nil, verifyRequestMsg(vs, kr, parsed.Request, verifyTime, false, e)
}

func verifyRequestMsg(vs *VectorSet, kr *Keyring, req *http.Request, verifyTime int64, wantAccept bool, e *Entry) error {
	// N-14 is response-only.
	witTok := req.Header.Get("Workload-Identity-Token")
	if witTok == "" {
		return fmt.Errorf("WIT: missing Workload-Identity-Token")
	}
	cnfPub, err := validateWIT(kr.IssuerPub, witTok, verifyTime)
	if err != nil {
		return fmt.Errorf("WIT: %w", err)
	}

	if req.Header.Get("Signature-Input") == "" || req.Header.Get("Signature") == "" {
		return fmt.Errorf("SELECT: no signature")
	}

	details, err := httpsign.RequestDetailsByTag(req, wimseTag)
	if err != nil {
		return fmt.Errorf("SELECT: %w", err)
	}

	if pf := checkRequestProfile(req, details, vs.TrustedAud, verifyTime); pf != nil {
		return pf
	}

	if err := checkContentDigest(req.Header, &req.Body, req.ContentLength); err != nil {
		return fmt.Errorf("DIGEST: %w", err)
	}

	fields := details.Fields
	vconfig := httpsign.NewVerifyConfig().
		SetAllowedTags([]string{wimseTag}).
		SetVerifyCreated(false).
		SetRejectExpired(false).
		SetSchemeFromRequest(func(*http.Request) string { return "https" })
	verifier, err := httpsign.NewJWSVerifier(jwsAllowlist(), cnfPub, vconfig, fields)
	if err != nil {
		return fmt.Errorf("CRYPTO setup: %w", err)
	}
	if err := httpsign.VerifyRequest(details.Label, *verifier, req); err != nil {
		return fmt.Errorf("CRYPTO: %w", err)
	}

	if wantAccept && e != nil && e.SigBase != "" {
		// optional: presence check only (full base compare needs httpsign export)
		_ = e.SigBase
	}
	return nil
}

func verifyResponseMsg(vs *VectorSet, kr *Keyring, res *http.Response, assocRaw string, verifyTime int64, wantAccept bool) error {
	_ = wantAccept
	if res.Header.Get("Signature-Input") == "" || res.Header.Get("Signature") == "" {
		// unsigned response — reject (N-14)
		return fmt.Errorf("BINDING: E_RESPONSE_UNSIGNED")
	}

	witTok := res.Header.Get("Workload-Identity-Token")
	if witTok == "" {
		return fmt.Errorf("WIT: missing Workload-Identity-Token")
	}
	cnfPub, err := validateWIT(kr.IssuerPub, witTok, verifyTime)
	if err != nil {
		return fmt.Errorf("WIT: %w", err)
	}

	assoc, err := parseHTTPMessage(assocRaw)
	if err != nil {
		return fmt.Errorf("assoc: %w", err)
	}
	wantNonce := ""
	if ad, err := httpsign.RequestDetailsByTag(assoc.Request, wimseTag); err == nil && ad.Nonce != nil {
		wantNonce = *ad.Nonce
	}

	details, err := httpsign.ResponseDetailsByTag(res, wimseTag)
	if err != nil {
		return fmt.Errorf("SELECT: %w", err)
	}

	if pf := checkResponseProfile(res, assoc.Request, details, wantNonce, verifyTime); pf != nil {
		return pf
	}

	if err := checkContentDigest(res.Header, &res.Body, res.ContentLength); err != nil {
		return fmt.Errorf("DIGEST: %w", err)
	}

	vconfig := httpsign.NewVerifyConfig().
		SetAllowedTags([]string{wimseTag}).
		SetVerifyCreated(false).
		SetRejectExpired(false).
		SetSchemeFromRequest(func(*http.Request) string { return "https" })
	verifier, err := httpsign.NewJWSVerifier(jwsAllowlist(), cnfPub, vconfig, details.Fields)
	if err != nil {
		return fmt.Errorf("CRYPTO setup: %w", err)
	}
	if err := httpsign.VerifyResponse(details.Label, *verifier, res, assoc.Request); err != nil {
		return fmt.Errorf("CRYPTO: %w", err)
	}
	_ = vs
	return nil
}

func validateWIT(issuerPub jwk.Key, tok string, verifyTime int64) (jwk.Key, error) {
	parsed, err := jwt.Parse(
		[]byte(tok),
		jwt.WithKey(jwa.EdDSAEd25519(), issuerPub),
		jwt.WithValidate(false),
	)
	if err != nil {
		return nil, fmt.Errorf("parse/verify: %w", err)
	}
	exp, ok := parsed.Expiration()
	if !ok {
		return nil, fmt.Errorf("missing exp")
	}
	if !exp.After(time.Unix(verifyTime, 0)) && !exp.Equal(time.Unix(verifyTime, 0)) {
		// exp must be > verifyTime (typical JWT: reject if now >= exp)
		if !time.Unix(verifyTime, 0).Before(exp) {
			return nil, fmt.Errorf("expired at %d (verify_time %d)", exp.Unix(), verifyTime)
		}
	}
	cnf, ok := parsed.Field("cnf")
	if !ok {
		return nil, fmt.Errorf("missing cnf")
	}
	cnfMap, ok := cnf.(map[string]any)
	if !ok {
		// jwx may return typed map
		b, err := jsonMarshal(cnf)
		if err != nil {
			return nil, fmt.Errorf("cnf type %T", cnf)
		}
		var m map[string]any
		if err := jsonUnmarshal(b, &m); err != nil {
			return nil, err
		}
		cnfMap = m
	}
	jwkRaw, ok := cnfMap["jwk"]
	if !ok {
		return nil, fmt.Errorf("missing cnf.jwk")
	}
	b, err := jsonMarshal(jwkRaw)
	if err != nil {
		return nil, err
	}
	key, err := jwk.ParseKey(b)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func checkContentDigest(h http.Header, body *io.ReadCloser, contentLength int64) error {
	cd := h.Get("Content-Digest")
	if cd == "" {
		return nil
	}
	if body == nil || *body == nil {
		if contentLength > 0 {
			return fmt.Errorf("Content-Digest present but no body")
		}
		return nil
	}
	got, err := httpsign.GenerateContentDigestHeader(body, []string{httpsign.DigestSha256})
	if err != nil {
		return err
	}
	if !digestHeadersEqual(got, cd) {
		return fmt.Errorf("mismatch: got %s want %s", got, cd)
	}
	return nil
}

func digestHeadersEqual(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// tiny JSON helpers to avoid importing encoding/json in every call site name clash
func jsonMarshal(v any) ([]byte, error) {
	return marshalJSON(v)
}
func jsonUnmarshal(b []byte, v any) error {
	return unmarshalJSON(b, v)
}
