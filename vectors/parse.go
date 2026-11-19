package vectors

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

const (
	wimseTag      = "wimse-workload-to-workload"
	defaultT0     = int64(1795000000)
	defaultVerify = int64(60)
	vectorSetPath = "testdata/s01-vector-set-v4.md"
	anchorPrefix  = "机读锚｜"
)

var (
	anchorRE   = regexp.MustCompile(`(?m)^[ \t]*-?[ \t]*机读锚｜(.+)$`)
	// Capture through the closing fence so a final body newline before ``` is preserved.
	fenceRE = regexp.MustCompile("(?s)```(?:json|text|http)?\\s*\\n(.*?)```")
	jwkLineRE  = regexp.MustCompile(`公钥 JWK：(\{.*\})`)
	privDRE    = regexp.MustCompile(`私钥 d：([A-Za-z0-9_-]+)`)
	witBlockRE = regexp.MustCompile(`(?m)^\*\*WIT-([ABC])\*\*[^\n]*\n+(eyJ[A-Za-z0-9._-]+)`)
	t0OffsetRE = regexp.MustCompile(`^T0([+-]\d+)$`)
	witPhRE = regexp.MustCompile(`\[WIT-([ABC])，§2 全文\]`)
)

// VectorSet is the parsed Zenodo v4 document.
type VectorSet struct {
	T0            int64
	DefaultOffset int64
	TrustedAud    map[string]struct{}
	WITs          map[string]string // "A","B","C" -> compact JWS
	Keys          map[string]keyMaterial
	Entries       []Entry
	PositivesByID map[string]*Entry
}

type keyMaterial struct {
	Name   string
	PubJWK string
	PrivD  string
}

// Entry is one P-/N-/O- vector.
type Entry struct {
	ID          string
	Kind        string // positive | negative-message | negative-behavior | observation
	Mode        string
	Base        string
	SigMode     string // literal | regen | none | probe
	Expect      string // ACCEPT | REJECT | CLIENT_REJECT | NONCONFORMANT
	VerifyTime  int64
	VerifyTimes []evalLeg
	Mutation    Mutation
	Message     string
	SigBase     string
	RawAnchor   string
	SkipReason  string
}

type evalLeg struct {
	VerifyTime int64
	Expect     string
}

// Mutation describes a negative-message transform.
type Mutation struct {
	Op        string
	Component string
	Param     string
	Member    string
	Body      string
	Note      string
	Raw       string
}

func LoadVectorSet(path string) (*VectorSet, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseVectorSet(string(b))
}

func ParseVectorSet(doc string) (*VectorSet, error) {
	vs := &VectorSet{
		T0:            defaultT0,
		DefaultOffset: defaultVerify,
		TrustedAud:    map[string]struct{}{},
		WITs:          map[string]string{},
		Keys:          map[string]keyMaterial{},
		PositivesByID: map[string]*Entry{},
	}

	if m := regexp.MustCompile(`(?m)^t0:\s*(\d+)`).FindStringSubmatch(doc); len(m) == 2 {
		vs.T0, _ = strconv.ParseInt(m[1], 10, 64)
	}
	if m := regexp.MustCompile(`(?m)^default_verify_offset_seconds:\s*(\d+)`).FindStringSubmatch(doc); len(m) == 2 {
		vs.DefaultOffset, _ = strconv.ParseInt(m[1], 10, 64)
	}

	for _, a := range []string{
		"https://svcb.example.com/gimme-ice-cream",
		"https://svcb.example.com/inventory/cones",
		"https://svcb.example.com/status",
		"https://svcb.example.com",
	} {
		vs.TrustedAud[a] = struct{}{}
	}

	parseKeys(doc, vs)
	for _, m := range witBlockRE.FindAllStringSubmatch(doc, -1) {
		vs.WITs[m[1]] = m[2]
	}
	if len(vs.WITs) != 3 {
		return nil, fmt.Errorf("expected 3 WITs, got %d: %v", len(vs.WITs), keysOf(vs.WITs))
	}

	entries, err := parseEntries(doc, vs)
	if err != nil {
		return nil, err
	}
	vs.Entries = entries
	for i := range vs.Entries {
		e := &vs.Entries[i]
		if e.Kind == "positive" {
			vs.PositivesByID[e.ID] = e
		}
	}
	return vs, nil
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func parseKeys(doc string, vs *VectorSet) {
	for _, name := range []string{"issuer-key", "vec-a-key", "vec-b-key", "vec-c-key", "other-key"} {
		idx := strings.Index(doc, `"kid":"`+name+`"`)
		if idx < 0 {
			continue
		}
		start := strings.LastIndex(doc[:idx], "公钥 JWK：")
		if start < 0 {
			continue
		}
		lineEnd := strings.Index(doc[start:], "\n")
		if lineEnd < 0 {
			continue
		}
		jm := jwkLineRE.FindStringSubmatch(doc[start : start+lineEnd])
		if jm == nil {
			continue
		}
		dm := privDRE.FindStringSubmatch(doc[start+lineEnd:])
		if dm == nil {
			continue
		}
		label := name
		switch name {
		case "issuer-key":
			label = "issuer"
		case "vec-a-key":
			label = "svcA"
		case "vec-b-key":
			label = "svcB"
		case "vec-c-key":
			label = "svcC"
		case "other-key":
			label = "other"
		}
		vs.Keys[label] = keyMaterial{Name: label, PubJWK: jm[1], PrivD: dm[1]}
	}
}

func parseEntries(doc string, vs *VectorSet) ([]Entry, error) {
	var out []Entry
	seen := map[string]bool{}

	for _, m := range anchorRE.FindAllStringSubmatchIndex(doc, -1) {
		line := doc[m[0]:m[1]]
		e, err := parseAnchorLine(strings.TrimSpace(line), vs)
		if err != nil {
			return nil, fmt.Errorf("anchor %q: %w", line, err)
		}
		if seen[e.ID] {
			continue
		}
		seen[e.ID] = true

		switch e.Kind {
		case "negative-behavior", "observation":
			e.SkipReason = "behavior/observation — not a static message verdict"
		case "positive":
			section := positiveSection(doc, m[0])
			e.Message, e.SigBase = extractMessageAndBase(section)
			e.Message = expandWITs(cleanMessage(e.Message), vs.WITs)
			e.SigBase = expandWITs(cleanBase(e.SigBase), vs.WITs)
			e.Message = attachKnownBodies(e.ID, e.Message)
		case "negative-message":
			if e.ID == "N-15" {
				section := negativeSection(doc, m[0])
				partial, _ := extractMessageAndBase(section)
				e.Message = expandWITs(cleanMessage(partial), vs.WITs)
			}
		}
		out = append(out, e)
	}
	return out, nil
}

func positiveSection(doc string, anchorIdx int) string {
	start := strings.LastIndex(doc[:anchorIdx], "\n### ")
	if start < 0 {
		start = 0
	} else {
		start++
	}
	end := len(doc)
	if next := strings.Index(doc[anchorIdx:], "\n### "); next >= 0 {
		end = anchorIdx + next
	}
	return doc[start:end]
}

func negativeSection(doc string, anchorIdx int) string {
	start := strings.LastIndex(doc[:anchorIdx], "\n- **N-")
	if start < 0 {
		start = strings.LastIndex(doc[:anchorIdx], "\n- **O-")
	}
	if start < 0 {
		start = 0
	} else {
		start++
	}
	end := len(doc)
	rest := doc[anchorIdx:]
	for _, pat := range []string{"\n- **N-", "\n- **O-", "\n## "} {
		if next := strings.Index(rest, pat); next >= 0 && anchorIdx+next < end {
			end = anchorIdx + next
		}
	}
	return doc[start:end]
}

func parseAnchorLine(line string, vs *VectorSet) (Entry, error) {
	line = strings.TrimPrefix(line, anchorPrefix)
	e := Entry{RawAnchor: line, VerifyTime: vs.T0 + vs.DefaultOffset}

	if m := regexp.MustCompile(`\bid=([A-Za-z0-9-]+)`).FindStringSubmatch(line); len(m) == 2 {
		e.ID = m[1]
	} else {
		return e, fmt.Errorf("missing id")
	}
	if m := regexp.MustCompile(`\bkind=([a-z-]+)`).FindStringSubmatch(line); len(m) == 2 {
		e.Kind = m[1]
	}
	if m := regexp.MustCompile(`\bmode=([a-z]+)`).FindStringSubmatch(line); len(m) == 2 {
		e.Mode = m[1]
	}
	if m := regexp.MustCompile(`\bbase=([^;]+)`).FindStringSubmatch(line); len(m) == 2 {
		e.Base = strings.TrimSpace(m[1])
		// Strip fullwidth annotations: P-01（独立构造）
		if i := strings.Index(e.Base, "（"); i >= 0 {
			e.Base = strings.TrimSpace(e.Base[:i])
		}
	}
	if m := regexp.MustCompile(`\bsig=([a-z]+)`).FindStringSubmatch(line); len(m) == 2 {
		e.SigMode = m[1]
	}
	if m := regexp.MustCompile(`expect=\{outcome:\s*([A-Z_]+)`).FindStringSubmatch(line); len(m) == 2 {
		e.Expect = m[1]
	}
	if m := regexp.MustCompile(`\bverify_time=(T0[+-]\d+)`).FindStringSubmatch(line); len(m) == 2 {
		e.VerifyTime = parseT0Offset(vs.T0, m[1])
	}

	if strings.Contains(line, "evaluations=[") {
		ev := regexp.MustCompile(`\{verify_time:\s*"(T0[+-]\d+)",\s*expect:\s*\{outcome:\s*([A-Z_]+)`).FindAllStringSubmatch(line, -1)
		for _, x := range ev {
			e.VerifyTimes = append(e.VerifyTimes, evalLeg{
				VerifyTime: parseT0Offset(vs.T0, x[1]),
				Expect:     x[2],
			})
		}
		if len(e.VerifyTimes) > 0 {
			e.Expect = ""
		}
	}

	if m := regexp.MustCompile(`mutation=\{([^}]*)\}`).FindStringSubmatch(line); len(m) == 2 {
		e.Mutation = parseMutation(m[1])
	}
	return e, nil
}

func parseMutation(s string) Mutation {
	mu := Mutation{Raw: s}
	if m := regexp.MustCompile(`op:\s*([a-z-]+)`).FindStringSubmatch(s); len(m) == 2 {
		mu.Op = m[1]
	}
	mu.Component = mutationStringField(s, "component")
	mu.Param = mutationStringField(s, "param")
	mu.Member = mutationStringField(s, "member")
	mu.Body = mutationStringField(s, "body")
	mu.Note = mutationStringField(s, "note")
	return mu
}

// mutationStringField reads key:"..." with JSON-style backslash escapes.
func mutationStringField(s, key string) string {
	re := regexp.MustCompile(key + `:\s*"((?:\\.|[^"\\])*)"`)
	m := re.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	unq, err := strconv.Unquote(`"` + m[1] + `"`)
	if err == nil {
		return unq
	}
	return strings.ReplaceAll(m[1], `\"`, `"`)
}

func parseT0Offset(t0 int64, s string) int64 {
	m := t0OffsetRE.FindStringSubmatch(s)
	if m == nil {
		return t0 + defaultVerify
	}
	off, _ := strconv.ParseInt(m[1], 10, 64)
	return t0 + off
}

func extractMessageAndBase(section string) (msg, base string) {
	fences := fenceRE.FindAllStringSubmatch(section, -1)
	for _, f := range fences {
		body := f[1] // may end with \n before closing ```
		trim := strings.TrimSpace(body)
		if strings.HasPrefix(trim, "{") || strings.Contains(body, "set_version:") {
			continue
		}
		// Partial Signature-* fences (e.g. N-15) before base detection — bases also mention "@method".
		if strings.Contains(body, "Signature-Input:") && strings.Contains(body, "Signature:") &&
			!strings.Contains(body, `"@signature-params"`) && !strings.Contains(body, "HTTP/1.") {
			if msg == "" {
				msg = strings.TrimSuffix(body, "\n")
			}
			continue
		}
		if strings.Contains(body, "HTTP/1.") ||
			strings.HasPrefix(trim, "GET ") || strings.HasPrefix(trim, "POST ") ||
			strings.HasPrefix(trim, "CONNECT ") || strings.HasPrefix(trim, "HTTP/") {
			if msg == "" {
				msg = body // keep trailing newline so response/request bodies match published digests
			}
			continue
		}
		if strings.Contains(body, `"@method":`) || strings.Contains(body, `"@status":`) ||
			strings.Contains(body, `"@authority":`) || strings.Contains(body, `"@signature-params"`) {
			if base == "" {
				base = strings.TrimSuffix(body, "\n")
			}
			continue
		}
	}
	return msg, base
}

func expandWITs(s string, wits map[string]string) string {
	return witPhRE.ReplaceAllStringFunc(s, func(m string) string {
		sub := witPhRE.FindStringSubmatch(m)
		if len(sub) == 2 {
			if tok, ok := wits[sub[1]]; ok {
				return tok
			}
		}
		return m
	})
}

func cleanBase(s string) string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		if i := strings.Index(line, " ["); i >= 0 {
			line = line[:i]
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func cleanMessage(s string) string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "Signature:") || strings.HasPrefix(line, "Signature-Input:") {
			if i := strings.Index(line, " ["); i >= 0 {
				line = line[:i]
			}
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func attachKnownBodies(id, msg string) string {
	switch id {
	case "P-03":
		if !strings.Contains(msg, "\n\n{") {
			body := `{"flavor":"vanilla","amount":1}`
			msg = strings.TrimRight(msg, "\n") + "\nContent-Length: " + strconv.Itoa(len(body)) + "\n\n" + body
		}
	}
	return msg
}
