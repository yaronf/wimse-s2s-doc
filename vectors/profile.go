package vectors

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/yaronf/httpsign"
)

type profileFailure struct {
	Stage string
	Code  string
	Err   error
}

func (f *profileFailure) Error() string {
	if f == nil {
		return ""
	}
	return fmt.Sprintf("%s/%s: %v", f.Stage, f.Code, f.Err)
}

func parseCoveredFromSigInput(sigInput, label string) []string {
	// Find label=( ... )
	idx := strings.Index(sigInput, label+"=")
	if idx < 0 {
		return nil
	}
	rest := sigInput[idx+len(label)+1:]
	if !strings.HasPrefix(rest, "(") {
		return nil
	}
	end := strings.Index(rest, ")")
	if end < 0 {
		return nil
	}
	inner := rest[1:end]
	var comps []string
	for _, p := range splitSFVList(inner) {
		comps = append(comps, strings.TrimSpace(p))
	}
	return comps
}

func splitSFVList(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			inQuote = !inQuote
			cur.WriteByte(c)
			continue
		}
		if c == ' ' && !inQuote {
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
			continue
		}
		cur.WriteByte(c)
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func hasComponent(comps []string, want string) bool {
	want = strings.ToLower(want)
	for _, c := range comps {
		name := strings.ToLower(strings.Trim(c, `"`))
		// strip params for bare compare of derived names
		if i := strings.Index(name, ";"); i >= 0 {
			base := name[:i]
			if base == strings.Trim(want, `"`) || name == want {
				return true
			}
			continue
		}
		if name == strings.Trim(want, `"`) || c == want {
			return true
		}
	}
	return false
}

func hasExactComponent(comps []string, want string) bool {
	for _, c := range comps {
		if c == want || strings.EqualFold(c, want) {
			return true
		}
	}
	// also accept without quotes
	w := strings.Trim(want, `"`)
	for _, c := range comps {
		if strings.Trim(c, `"`) == w {
			return true
		}
	}
	return false
}

func checkRequestProfile(req *http.Request, details *httpsign.MessageDetails, trusted map[string]struct{}, verifyTime int64) *profileFailure {
	sigInput := req.Header.Get("Signature-Input")
	comps := parseCoveredFromSigInput(sigInput, details.Label)

	method := req.Method
	if method == http.MethodConnect {
		if !hasComponent(comps, `"@method"`) && !hasComponent(comps, "@method") {
			return &profileFailure{"COVERAGE", "E_COVERAGE_MISSING", fmt.Errorf("CONNECT missing @method")}
		}
		if !hasComponent(comps, `"@authority"`) && !hasComponent(comps, "@authority") {
			return &profileFailure{"COVERAGE", "E_COVERAGE_MISSING", fmt.Errorf("CONNECT missing @authority")}
		}
		if hasComponent(comps, `"@path"`) || hasComponent(comps, "@path") ||
			hasComponent(comps, `"@query"`) || hasComponent(comps, "@query") {
			return &profileFailure{"COVERAGE", "E_COVERAGE_FORBIDDEN", fmt.Errorf("CONNECT must not cover @path/@query")}
		}
	} else {
		for _, need := range []string{"@method", "@path", "@query"} {
			if !hasComponent(comps, need) {
				return &profileFailure{"COVERAGE", "E_COVERAGE_MISSING", fmt.Errorf("missing %s", need)}
			}
		}
	}
	if !hasComponent(comps, "workload-identity-token") {
		return &profileFailure{"COVERAGE", "E_COVERAGE_MISSING", fmt.Errorf("missing workload-identity-token")}
	}

	// Body requires Content-Digest header and coverage.
	if req.Body != nil && req.ContentLength > 0 {
		if req.Header.Get("Content-Digest") == "" {
			return &profileFailure{"COVERAGE", "E_DIGEST_MISSING", fmt.Errorf("body without Content-Digest")}
		}
		if !hasComponent(comps, "content-digest") {
			return &profileFailure{"COVERAGE", "E_DIGEST_MISSING", fmt.Errorf("Content-Digest not covered")}
		}
	}

	if details.Created == nil {
		return &profileFailure{"PARAMS", "E_PARAM_MISSING", fmt.Errorf("missing created")}
	}
	if details.Expires == nil {
		return &profileFailure{"PARAMS", "E_PARAM_MISSING", fmt.Errorf("missing expires")}
	}
	if details.Nonce == nil || *details.Nonce == "" {
		return &profileFailure{"PARAMS", "E_PARAM_MISSING", fmt.Errorf("missing nonce")}
	}
	if details.Tag == nil || *details.Tag != wimseTag {
		return &profileFailure{"PARAMS", "E_PARAM_MISSING", fmt.Errorf("missing/wrong tag")}
	}
	if details.KeyID != nil {
		return &profileFailure{"PARAMS", "E_PARAM_FORBIDDEN", fmt.Errorf("keyid present")}
	}
	if details.Alg != "" {
		return &profileFailure{"PARAMS", "E_PARAM_FORBIDDEN", fmt.Errorf("alg present")}
	}
	aud, ok := details.CustomParams["wimse-aud"].(string)
	if !ok || aud == "" {
		return &profileFailure{"PARAMS", "E_PARAM_MISSING", fmt.Errorf("missing wimse-aud")}
	}
	if _, ok := trusted[aud]; !ok {
		return &profileFailure{"AUD", "E_AUD_MISMATCH", fmt.Errorf("aud %q not trusted", aud)}
	}

	created := details.Created.Unix()
	expires := details.Expires.Unix()
	if verifyTime < created || verifyTime > expires {
		return &profileFailure{"WINDOW", "E_WINDOW_OUTSIDE", fmt.Errorf("verify_time %d not in [%d,%d]", verifyTime, created, expires)}
	}
	return nil
}

func checkResponseProfile(res *http.Response, req *http.Request, details *httpsign.MessageDetails, wantReqNonce string, verifyTime int64) *profileFailure {
	sigInput := res.Header.Get("Signature-Input")
	comps := parseCoveredFromSigInput(sigInput, details.Label)

	if !hasComponent(comps, `"@status"`) && !hasComponent(comps, "@status") {
		return &profileFailure{"COVERAGE", "E_COVERAGE_MISSING", fmt.Errorf("missing @status")}
	}
	if !hasComponent(comps, "workload-identity-token") {
		return &profileFailure{"COVERAGE", "E_COVERAGE_MISSING", fmt.Errorf("missing workload-identity-token")}
	}
	for _, need := range []string{`"@method";req`, `"@path";req`, `"@query";req`} {
		// CONNECT request: must NOT cover @path;req / @query;req
		if req != nil && req.Method == http.MethodConnect {
			if need != `"@method";req` {
				continue
			}
		}
		if req != nil && req.Method == http.MethodConnect {
			if hasExactComponent(comps, `"@path";req`) || hasExactComponent(comps, `"@query";req`) {
				return &profileFailure{"COVERAGE", "E_COVERAGE_FORBIDDEN", fmt.Errorf("CONNECT response must not cover @path;req/@query;req")}
			}
		}
	}
	if req != nil && req.Method == http.MethodConnect {
		if hasExactComponent(comps, `"@path";req`) || hasExactComponent(comps, `"@query";req`) {
			return &profileFailure{"COVERAGE", "E_COVERAGE_FORBIDDEN", fmt.Errorf("CONNECT response must not cover path/query req")}
		}
		if !hasExactComponent(comps, `"@method";req`) && !hasComponent(comps, `@method;req`) {
			return &profileFailure{"COVERAGE", "E_COVERAGE_MISSING", fmt.Errorf("missing @method;req")}
		}
	} else {
		for _, need := range []string{"@method;req", "@path;req", "@query;req"} {
			found := false
			for _, c := range comps {
				n := strings.Trim(c, `"`)
				if n == need || strings.HasPrefix(n, strings.Split(need, ";")[0]+";") && strings.Contains(n, ";req") {
					// more precise:
					if n == need {
						found = true
						break
					}
				}
				if c == `"`+need+`"` || c == `"`+strings.Replace(need, ";", `";`, 1) {
					found = true
					break
				}
			}
			// Direct check
			if hasExactComponent(comps, `"`+need+`"`) || hasExactComponent(comps, need) {
				found = true
			}
			// "@method";req form
			parts := strings.SplitN(need, ";", 2)
			alt := `"` + parts[0] + `";` + parts[1]
			if hasExactComponent(comps, alt) {
				found = true
			}
			if !found {
				return &profileFailure{"COVERAGE", "E_COVERAGE_MISSING", fmt.Errorf("missing %s", need)}
			}
		}
	}

	if res.Body != nil && res.ContentLength > 0 {
		if res.Header.Get("Content-Digest") == "" {
			return &profileFailure{"COVERAGE", "E_DIGEST_MISSING", fmt.Errorf("body without Content-Digest")}
		}
		if !hasComponent(comps, "content-digest") {
			return &profileFailure{"COVERAGE", "E_DIGEST_MISSING", fmt.Errorf("Content-Digest not covered")}
		}
	}

	if details.Created == nil || details.Expires == nil || details.Nonce == nil || details.Tag == nil {
		return &profileFailure{"PARAMS", "E_PARAM_MISSING", fmt.Errorf("missing created/expires/nonce/tag")}
	}
	if *details.Tag != wimseTag {
		return &profileFailure{"PARAMS", "E_PARAM_MISSING", fmt.Errorf("wrong tag")}
	}
	if details.KeyID != nil {
		return &profileFailure{"PARAMS", "E_PARAM_FORBIDDEN", fmt.Errorf("keyid present")}
	}
	if details.Alg != "" {
		return &profileFailure{"PARAMS", "E_PARAM_FORBIDDEN", fmt.Errorf("alg present")}
	}
	got, ok := details.CustomParams["wimse-req-nonce"].(string)
	if !ok || got == "" {
		return &profileFailure{"PARAMS", "E_REQNONCE_MISSING", fmt.Errorf("missing wimse-req-nonce")}
	}
	if wantReqNonce != "" && got != wantReqNonce {
		return &profileFailure{"BINDING", "E_REQNONCE_MISMATCH", fmt.Errorf("got %q want %q", got, wantReqNonce)}
	}

	created := details.Created.Unix()
	expires := details.Expires.Unix()
	if verifyTime < created || verifyTime > expires {
		return &profileFailure{"WINDOW", "E_WINDOW_OUTSIDE", fmt.Errorf("verify_time %d not in [%d,%d]", verifyTime, created, expires)}
	}
	return nil
}
