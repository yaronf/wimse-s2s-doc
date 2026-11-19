package vectors

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/yaronf/httpsign"
)

func baseID(base string) string {
	base = strings.TrimSpace(base)
	if i := strings.IndexAny(base, "（+"); i >= 0 {
		base = strings.TrimSpace(base[:i])
	}
	return base
}

// buildNegativeMessage constructs the HTTP message for a negative-message entry.
func buildNegativeMessage(vs *VectorSet, kr *Keyring, e *Entry) (msg string, assocReq string, err error) {
	switch e.ID {
	case "N-14":
		p2 := vs.PositivesByID["P-02"]
		p1 := vs.PositivesByID["P-01"]
		if p2 == nil || p1 == nil {
			return "", "", fmt.Errorf("missing P-01/P-02")
		}
		return stripSignatureHeaders(p2.Message), p1.Message, nil
	case "N-15":
		p1 := vs.PositivesByID["P-01"]
		if p1 == nil {
			return "", "", fmt.Errorf("missing P-01")
		}
		msg, err := overlayN15(p1.Message, e.Message)
		return msg, "", err
	case "N-21":
		p2 := vs.PositivesByID["P-02"]
		p4 := vs.PositivesByID["P-04"]
		if p2 == nil || p4 == nil {
			return "", "", fmt.Errorf("missing P-02/P-04")
		}
		return regenMutated(kr, e, p2.Message, p4.Message)
	}

	bid := baseID(e.Base)
	base := vs.PositivesByID[bid]
	if base == nil {
		return "", "", fmt.Errorf("unknown base %q", e.Base)
	}
	assoc := ""
	if bid == "P-02" {
		if p1 := vs.PositivesByID["P-01"]; p1 != nil {
			assoc = p1.Message
		}
	}

	switch e.SigMode {
	case "literal", "":
		if e.Mutation.Op == "set-verify-time" {
			return base.Message, assoc, nil
		}
		out, err := applyLiteralMutation(base.Message, e.Mutation)
		return out, assoc, err
	case "regen":
		return regenMutated(kr, e, base.Message, assoc)
	case "none":
		return stripSignatureHeaders(base.Message), assoc, nil
	default:
		return "", "", fmt.Errorf("unsupported sig mode %q", e.SigMode)
	}
}

func overlayN15(p01, partial string) (string, error) {
	var sigInput, sig string
	for _, line := range strings.Split(partial, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Signature-Input:") {
			sigInput = strings.TrimSpace(strings.TrimPrefix(line, "Signature-Input:"))
		}
		if strings.HasPrefix(line, "Signature:") {
			sig = strings.TrimSpace(strings.TrimPrefix(line, "Signature:"))
			if i := strings.Index(sig, " ["); i >= 0 {
				sig = sig[:i]
			}
		}
	}
	if sigInput == "" || sig == "" {
		return "", fmt.Errorf("N-15 missing Signature-Input/Signature")
	}
	var out []string
	for _, line := range strings.Split(p01, "\n") {
		switch {
		case strings.HasPrefix(line, "Signature-Input:"):
			out = append(out, "Signature-Input: "+sigInput)
		case strings.HasPrefix(line, "Signature:"):
			out = append(out, "Signature: "+sig)
		default:
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n"), nil
}

func stripSignatureHeaders(raw string) string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, "Signature:") || strings.HasPrefix(line, "Signature-Input:") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func applyLiteralMutation(raw string, mu Mutation) (string, error) {
	switch mu.Op {
	case "remove-component":
		comp := normalizeCompToken(mu.Component)
		out, err := mutateSigInputComponents(raw, "", func(comps []string, params string) (string, error) {
			var kept []string
			for _, c := range comps {
				if componentMatches(c, comp) {
					continue
				}
				kept = append(kept, c)
			}
			return "(" + strings.Join(kept, " ") + ")" + params, nil
		})
		if err != nil {
			return "", err
		}
		if strings.Contains(strings.ToLower(comp), "content-digest") {
			out = removeHeader(out, "Content-Digest")
		}
		return out, nil
	case "set-body":
		return replaceBody(raw, mu.Body), nil
	case "remove-param":
		return mutateSigInputParams(raw, "", func(params string) string {
			return removeParam(params, mu.Param)
		})
	default:
		return "", fmt.Errorf("literal mutation op %q not supported", mu.Op)
	}
}

func normalizeCompToken(c string) string {
	c = strings.TrimSpace(c)
	if i := strings.Index(c, "（"); i >= 0 {
		c = c[:i]
	}
	return strings.TrimSpace(c)
}

func componentMatches(have, want string) bool {
	h := strings.Trim(have, `"`)
	w := strings.Trim(want, `"`)
	h = strings.Split(h, ";")[0]
	w = strings.Split(w, ";")[0]
	return strings.EqualFold(h, w)
}

func removeHeader(raw, name string) string {
	var out []string
	prefix := strings.ToLower(name) + ":"
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(strings.ToLower(line), prefix) {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func replaceBody(raw, body string) string {
	parts := strings.SplitN(raw, "\n\n", 2)
	head := parts[0]
	var lines []string
	hasCL := false
	for _, line := range strings.Split(head, "\n") {
		if strings.HasPrefix(strings.ToLower(line), "content-length:") {
			lines = append(lines, fmt.Sprintf("Content-Length: %d", len(body)))
			hasCL = true
			continue
		}
		lines = append(lines, line)
	}
	if !hasCL {
		lines = append(lines, fmt.Sprintf("Content-Length: %d", len(body)))
	}
	return strings.Join(lines, "\n") + "\n\n" + body
}

func mutateSigInputComponents(raw, label string, fn func(comps []string, params string) (string, error)) (string, error) {
	return mutateSigInput(raw, label, func(inner, params string) (string, error) {
		return fn(splitSFVList(inner), params)
	})
}

func mutateSigInputParams(raw, label string, fn func(params string) string) (string, error) {
	return mutateSigInput(raw, label, func(inner, params string) (string, error) {
		return "(" + inner + ")" + fn(params), nil
	})
}

func mutateSigInput(raw, label string, fn func(inner, params string) (string, error)) (string, error) {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		if !strings.HasPrefix(line, "Signature-Input:") {
			out = append(out, line)
			continue
		}
		val := strings.TrimSpace(strings.TrimPrefix(line, "Signature-Input:"))
		members := splitDictMembers(val)
		var rewritten []string
		mutatedOnce := false
		for _, mem := range members {
			name, rest, ok := strings.Cut(mem, "=")
			if !ok {
				rewritten = append(rewritten, mem)
				continue
			}
			name = strings.TrimSpace(name)
			if label != "" && name != label {
				rewritten = append(rewritten, mem)
				continue
			}
			if label == "" && mutatedOnce {
				rewritten = append(rewritten, mem)
				continue
			}
			rest = strings.TrimSpace(rest)
			if !strings.HasPrefix(rest, "(") {
				return "", fmt.Errorf("bad Signature-Input member %q", mem)
			}
			end := strings.Index(rest, ")")
			if end < 0 {
				return "", fmt.Errorf("unclosed component list")
			}
			inner := rest[1:end]
			params := rest[end+1:]
			newRest, err := fn(inner, params)
			if err != nil {
				return "", err
			}
			rewritten = append(rewritten, name+"="+newRest)
			mutatedOnce = true
		}
		out = append(out, "Signature-Input: "+strings.Join(rewritten, ", "))
	}
	return strings.Join(out, "\n"), nil
}

func splitDictMembers(s string) []string {
	var out []string
	var cur strings.Builder
	depth := 0
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inQuote = !inQuote
			cur.WriteByte(c)
		case !inQuote && c == '(':
			depth++
			cur.WriteByte(c)
		case !inQuote && c == ')':
			depth--
			cur.WriteByte(c)
		case !inQuote && depth == 0 && c == ',':
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, strings.TrimSpace(cur.String()))
	}
	return out
}

func removeParam(params, name string) string {
	name = strings.TrimSpace(name)
	re := regexp.MustCompile(`;?\s*` + regexp.QuoteMeta(name) + `(?:=(?:[^;]*|"[^"]*"))?`)
	return re.ReplaceAllString(params, "")
}

func setOrAddParam(params, assignment string) string {
	name := assignment
	if i := strings.Index(assignment, "="); i >= 0 {
		name = assignment[:i]
	}
	params = removeParam(params, name)
	if !strings.HasPrefix(assignment, ";") {
		assignment = ";" + assignment
	}
	return params + assignment
}

func regenMutated(kr *Keyring, e *Entry, baseMsg, assocMsg string) (string, string, error) {
	raw := baseMsg
	mu := e.Mutation
	var err error

	switch mu.Op {
	case "add-component":
		comp := mu.Component
		if !strings.HasPrefix(comp, `"`) && (strings.HasPrefix(comp, "@") || !strings.Contains(comp, `"`)) {
			if strings.Contains(comp, ";") {
				// "@path";req form already quoted in anchor
				comp = mu.Component
			} else {
				comp = `"` + comp + `"`
			}
		}
		raw, err = mutateSigInputComponents(raw, "", func(comps []string, params string) (string, error) {
			comps = append(comps, comp)
			return "(" + strings.Join(comps, " ") + ")" + params, nil
		})
	case "add-param":
		raw, err = mutateSigInputParams(raw, "", func(params string) string {
			return setOrAddParam(params, mu.Param)
		})
	case "remove-param":
		raw, err = mutateSigInputParams(raw, "", func(params string) string {
			return removeParam(params, mu.Param)
		})
	case "set-param":
		raw, err = mutateSigInputParams(raw, mu.Member, func(params string) string {
			return setOrAddParam(params, mu.Param)
		})
	default:
		return "", "", fmt.Errorf("regen op %q not supported for %s", mu.Op, e.ID)
	}
	if err != nil {
		return "", "", err
	}

	signed, err := resignMessage(kr, e, raw, assocMsg)
	return signed, assocMsg, err
}

func resignMessage(kr *Keyring, e *Entry, raw, assocMsg string) (string, error) {
	parsed, err := parseHTTPMessage(raw)
	if err != nil {
		return "", err
	}
	if parsed.IsResponse {
		return resignResponse(kr, e, parsed.Response, assocMsg)
	}
	return resignRequest(kr, e, parsed.Request)
}

func resignRequest(kr *Keyring, e *Entry, req *http.Request) (string, error) {
	sigInput := req.Header.Get("Signature-Input")
	members := splitDictMembers(sigInput)
	req.Header.Del("Signature")
	req.Header.Del("Signature-Input")

	var allIn, allSig []string
	for _, mem := range members {
		label, rest, ok := strings.Cut(mem, "=")
		if !ok {
			continue
		}
		label = strings.TrimSpace(label)
		details := parseMemberRest(rest)
		priv, fields := pickRequestKeyAndFields(kr, e, label, details)
		cfg := httpsign.NewSignConfig().SignAlg(false).SetTag(details.tag)
		setFakeCreated(cfg, details.created)
		if details.expires != 0 {
			cfg.SetExpires(details.expires)
		}
		if details.nonce != "" {
			cfg.SetNonce(details.nonce)
		}
		if details.keyID != "" {
			cfg.SetKeyID(details.keyID)
		}
		for k, v := range details.custom {
			cfg.AddCustomParam(k, v)
		}
		for _, fl := range details.flags {
			cfg.AddCustomParam(fl, true)
		}
		signer, err := httpsign.NewJWSSignerFromJWK(priv, cfg, fields)
		if err != nil {
			return "", err
		}
		tmp := cloneRequest(req)
		tmp.Header.Del("Signature")
		tmp.Header.Del("Signature-Input")
		in, sig, err := httpsign.SignRequest(label, *signer, tmp)
		if err != nil {
			return "", fmt.Errorf("sign %s: %w", label, err)
		}
		// N-07: inject alg after signing (reserved param not addable via AddCustomParam)
		if e.Mutation.Op == "add-param" && strings.HasPrefix(e.Mutation.Param, "alg=") {
			in = injectParam(in, e.Mutation.Param)
		}
		allIn = append(allIn, in)
		allSig = append(allSig, sig)
	}
	req.Header.Set("Signature-Input", strings.Join(allIn, ", "))
	req.Header.Set("Signature", strings.Join(allSig, ", "))
	return dumpRequestMessage(req)
}

func injectParam(sigInputMember, assignment string) string {
	if !strings.HasPrefix(assignment, ";") {
		assignment = ";" + assignment
	}
	return sigInputMember + assignment
}

func resignResponse(kr *Keyring, e *Entry, res *http.Response, assocMsg string) (string, error) {
	assoc, err := parseHTTPMessage(assocMsg)
	if err != nil {
		return "", err
	}
	sigInput := res.Header.Get("Signature-Input")
	members := splitDictMembers(sigInput)
	res.Header.Del("Signature")
	res.Header.Del("Signature-Input")

	var allIn, allSig []string
	for _, mem := range members {
		label, rest, ok := strings.Cut(mem, "=")
		if !ok {
			continue
		}
		label = strings.TrimSpace(label)
		details := parseMemberRest(rest)
		priv := kr.SvcB
		fields := fieldsFromComponents(details.comps)
		cfg := httpsign.NewSignConfig().SignAlg(false).SetTag(details.tag)
		setFakeCreated(cfg, details.created)
		if details.expires != 0 {
			cfg.SetExpires(details.expires)
		}
		if details.nonce != "" {
			cfg.SetNonce(details.nonce)
		}
		for k, v := range details.custom {
			cfg.AddCustomParam(k, v)
		}
		signer, err := httpsign.NewJWSSignerFromJWK(priv, cfg, fields)
		if err != nil {
			return "", err
		}
		in, sig, err := httpsign.SignResponse(label, *signer, res, assoc.Request)
		if err != nil {
			return "", err
		}
		allIn = append(allIn, in)
		allSig = append(allSig, sig)
		res.Header.Del("Signature")
		res.Header.Del("Signature-Input")
	}
	res.Header.Set("Signature-Input", strings.Join(allIn, ", "))
	res.Header.Set("Signature", strings.Join(allSig, ", "))
	_ = e
	return dumpResponseMessage(res)
}

type memberDetails struct {
	comps   []string
	created int64
	expires int64
	nonce   string
	tag     string
	keyID   string
	custom  map[string]any
	flags   []string
	wantAlg string
}

func parseMemberRest(rest string) memberDetails {
	md := memberDetails{custom: map[string]any{}}
	rest = strings.TrimSpace(rest)
	if strings.HasPrefix(rest, "(") {
		end := strings.Index(rest, ")")
		md.comps = splitSFVList(rest[1:end])
		rest = rest[end+1:]
	}
	for _, p := range strings.Split(rest, ";") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		name, val, ok := strings.Cut(p, "=")
		if !ok {
			md.flags = append(md.flags, name)
			continue
		}
		val = strings.Trim(val, `"`)
		switch name {
		case "created":
			fmt.Sscan(val, &md.created)
		case "expires":
			fmt.Sscan(val, &md.expires)
		case "nonce":
			md.nonce = val
		case "tag":
			md.tag = val
		case "keyid":
			md.keyID = val
		case "alg":
			md.wantAlg = val
		default:
			md.custom[name] = val
		}
	}
	return md
}

func pickRequestKeyAndFields(kr *Keyring, e *Entry, label string, md memberDetails) (jwk.Key, httpsign.Fields) {
	fields := fieldsFromComponents(md.comps)
	if md.keyID == "other-key" || (label == "sig1" && strings.Contains(e.Base, "P-06") && md.tag != wimseTag) {
		return kr.Other, fields
	}
	if label == "sig1" && e.ID == "N-08" {
		return kr.Other, fields
	}
	switch baseID(e.Base) {
	case "P-03":
		return kr.SvcC, fields
	case "P-02":
		return kr.SvcB, fields
	default:
		return kr.SvcA, fields
	}
}

func fieldsFromComponents(comps []string) httpsign.Fields {
	f := httpsign.NewFields()
	for _, c := range comps {
		c = strings.TrimSpace(c)
		name := c
		req := false
		if strings.HasPrefix(c, `"`) {
			if i := strings.Index(c[1:], `"`); i >= 0 {
				name = c[1 : 1+i]
				rest := c[1+i+1:]
				if strings.Contains(rest, "req") {
					req = true
				}
			}
		} else {
			name = strings.Trim(c, `"`)
			if i := strings.Index(name, ";"); i >= 0 {
				if strings.Contains(name[i+1:], "req") {
					req = true
				}
				name = name[:i]
			}
		}
		if req {
			f.AddRequestComponent(name)
		} else {
			f.AddHeaders(name)
		}
	}
	return *f
}
