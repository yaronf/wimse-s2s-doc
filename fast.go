package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strings"

	"github.com/cloudflare/circl/hpke"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/yaronf/httpsign"
	"golang.org/x/crypto/hkdf"
)

const (
	fastKemSuite   = "dhkem-p256-hkdf-sha256"
	fastSessionTag = "wimse-httpsig-session"
	fastInfoLabel  = "wimse-httpsig-session"
)

// Opaque ticket placeholders (not AEAD). Longer than session_id (16 octets) so the
// examples stay visually distinct from the session identifier. Dumps truncate the
// ticket base64 with "..." for draft includes (sign/verify still use the full value).
var (
	ticketParamDumpRE = regexp.MustCompile(`(wimse-ticket-(?:server|client)=:)([^:]+)(:)`)

	ticketServerPlaceholder = []byte{
		0x74, 0x69, 0x63, 0x6b, 0x65, 0x74, 0x2d, 0x73, // "ticket-s"
		0x65, 0x72, 0x76, 0x65, 0x72, 0x2d, 0x70, 0x6c, // "erver-pl"
		0x61, 0x63, 0x65, 0x68, 0x6f, 0x6c, 0x64, 0x65, // "aceholde"
		0x72, 0x2d, 0x6e, 0x6f, 0x74, 0x2d, 0x61, 0x65, // "r-not-ae"
		0xad, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
		0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
		0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, // 64 octets
	}
	ticketClientPlaceholder = []byte{
		0x74, 0x69, 0x63, 0x6b, 0x65, 0x74, 0x2d, 0x63, // "ticket-c"
		0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2d, 0x70, 0x6c, // "lient-pl"
		0x61, 0x63, 0x65, 0x68, 0x6f, 0x6c, 0x64, 0x65, // "aceholde"
		0x72, 0x2d, 0x6e, 0x6f, 0x74, 0x2d, 0x61, 0x65, // "r-not-ae"
		0xad, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
		0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
		0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
		0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e,
		0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
		0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, // 80 octets
	}
)

type sessionKeys struct {
	kReq      []byte
	kRes      []byte
	sessionID []byte
}

func deriveSessionKeys(sharedSecret []byte, suite, reqNonce, respNonce, clientWIT, serverWIT string) sessionKeys {
	salt := make([]byte, 32) // all zeros
	prk := hkdf.Extract(sha256.New, sharedSecret, salt)

	var info []byte
	info = append(info, []byte(fastInfoLabel)...)
	info = append(info, 0x00)
	info = append(info, []byte(suite)...)
	info = append(info, 0x00)
	info = append(info, []byte(reqNonce)...)
	info = append(info, 0x00)
	info = append(info, []byte(respNonce)...)
	info = append(info, 0x00)
	hClient := sha256.Sum256([]byte(clientWIT))
	hServer := sha256.Sum256([]byte(serverWIT))
	info = append(info, hClient[:]...)
	info = append(info, hServer[:]...)

	okm := make([]byte, 80)
	_, err := io.ReadFull(hkdf.Expand(sha256.New, prk, info), okm)
	failIf(err, "HKDF-Expand failed")

	return sessionKeys{
		kReq:      okm[0:32],
		kRes:      okm[32:64],
		sessionID: okm[64:80],
	}
}

func sessionRequestFields() *httpsign.Fields {
	return httpsign.NewFields().
		AddHeaders("@method", "@path", "@query").
		AddHeaderOptional("Content-Type").
		AddHeaderOptional("Content-Digest")
}

func sessionResponseFields() *httpsign.Fields {
	return httpsign.NewFields().
		AddHeader("@status").
		AddHeaderOptional("Content-Type").
		AddHeaderOptional("Content-Digest").
		AddRequestComponent("@method").
		AddRequestComponent("@path").
		AddRequestComponent("@query")
}

func verifySessionRequest(req *http.Request, key []byte, fields httpsign.Fields) (string, *httpsign.MessageDetails) {
	details, err := httpsign.RequestDetailsByTag(req, fastSessionTag)
	failIf(err, "Failed to get session request signature details")

	vconfig := httpsign.NewVerifyConfig().SetAllowedTags([]string{fastSessionTag})
	verifier, err := httpsign.NewHMACSHA256Verifier(key, vconfig, fields)
	failIf(err, "Failed to create session request verifier")
	failIf(httpsign.VerifyRequest(details.Label, *verifier, req), "Failed to verify session request")
	return details.Label, details
}

func verifySessionResponse(res *http.Response, req *http.Request, key []byte, fields httpsign.Fields, wantReqNonce string) (string, *httpsign.MessageDetails) {
	details, err := httpsign.ResponseDetailsByTag(res, fastSessionTag)
	failIf(err, "Failed to get session response signature details")

	vconfig := httpsign.NewVerifyConfig().SetAllowedTags([]string{fastSessionTag})
	verifier, err := httpsign.NewHMACSHA256Verifier(key, vconfig, fields)
	failIf(err, "Failed to create session response verifier")
	failIf(httpsign.VerifyResponse(details.Label, *verifier, res, req), "Failed to verify session response")
	got, ok := details.CustomParams["wimse-req-nonce"].(string)
	if !ok || got != wantReqNonce {
		failIf(fmt.Errorf("got %v, want %q", details.CustomParams["wimse-req-nonce"], wantReqNonce), "session wimse-req-nonce mismatch")
	}
	return details.Label, details
}

type fastExamples struct {
	hsReqDump   []byte
	hsResDump   []byte
	sessReqDump []byte
	sessResDump []byte
	sessionID   []byte
	suite       string
}

func generateFastExamples(
	callerKey, calleeKey jwk.Key,
	callerWIT, calleeWIT string,
	aud string,
	hsReqNonce, hsResNonce string,
	sessReqNonce, sessResNonce string,
	expires int64,
	debug bool,
) fastExamples {
	scheme := hpke.KEM_P256_HKDF_SHA256.Scheme()
	pkR, skR, err := scheme.GenerateKeyPair()
	failIf(err, "Failed to generate DHKEM recipient key pair")

	pkRBytes, err := pkR.MarshalBinary()
	failIf(err, "Failed to marshal pkR")

	enc, sharedSecret, err := scheme.Encapsulate(pkR)
	failIf(err, "DHKEM Encap failed")

	// Sanity: client Decap must match server Encap shared_secret.
	ssClient, err := scheme.Decapsulate(skR, enc)
	failIf(err, "DHKEM Decap failed")
	if !hmacEqual(sharedSecret, ssClient) {
		failIf(fmt.Errorf("shared_secret mismatch"), "DHKEM Encap/Decap mismatch")
	}

	// --- Handshake request (base profile + kem params) ---
	rawHsReq := fmt.Sprintf(`GET /gimme-ice-cream?flavor=vanilla HTTP/1.1
Host: svcb.example.com
Workload-Identity-Token: %s

`, callerWIT)

	fieldsReq := requestFields()
	hsReqConfig := httpsign.NewSignConfig().SetTag(wimseTag).
		SetNonce(hsReqNonce).SignAlg(false).SetExpires(expires).
		AddCustomParam("wimse-aud", aud).
		AddCustomParam("wimse-sign-response", true).
		AddCustomParam("wimse-kem-suite", fastKemSuite).
		AddCustomParam("wimse-kem", pkRBytes)
	hsReqSigner, err := httpsign.NewJWSSignerFromJWK(callerKey, hsReqConfig, *fieldsReq)
	failIf(err, "Failed to create fast handshake request signer")

	hsReq, err := http.ReadRequest(bufio.NewReader(strings.NewReader(rawHsReq)))
	failIf(err, "Failed to read fast handshake request")
	ensureContentDigest(hsReq)

	sigInput, sig, err := httpsign.SignRequest("sig1", *hsReqSigner, hsReq)
	failIf(err, "Failed to sign fast handshake request")
	hsReq.Header.Set("Signature", sig)
	hsReq.Header.Set("Signature-Input", sigInput)

	callerPub, err := callerKey.PublicKey()
	failIf(err, "Failed to get caller public key")
	reqSigName, reqDetails := verifyRequestByTag(hsReq, callerPub, *fieldsReq)
	fmt.Printf("Verified fast handshake request %q (tag=%q)\n", reqSigName, *reqDetails.Tag)

	hsReqDump, err := httputil.DumpRequest(hsReq, true)
	failIf(err, "Could not dump fast handshake request")

	// --- Handshake response (base profile + enc + opaque ticket_server) ---
	hsResBody := "No ice cream today.\n"
	rawHsRes := fmt.Sprintf(`HTTP/1.1 404 Not Found
Workload-Identity-Token: %s
Content-Type: text/plain
Content-Length: %d

%s`, calleeWIT, len(hsResBody), hsResBody)

	fieldsRes := responseFields()
	hsResConfig := httpsign.NewSignConfig().SetTag(wimseTag).
		SetNonce(hsResNonce).SignAlg(false).SetExpires(expires + 2).
		AddCustomParam("wimse-req-nonce", hsReqNonce).
		AddCustomParam("wimse-kem-suite", fastKemSuite).
		AddCustomParam("wimse-kem", enc).
		AddCustomParam("wimse-ticket-server", ticketServerPlaceholder)
	hsResSigner, err := httpsign.NewJWSSignerFromJWK(calleeKey, hsResConfig, *fieldsRes)
	failIf(err, "Failed to create fast handshake response signer")

	hsRes, err := http.ReadResponse(bufio.NewReader(strings.NewReader(rawHsRes)), hsReq)
	failIf(err, "Failed to read fast handshake response")
	ensureResponseContentDigest(hsRes)

	sigInput, sig, err = httpsign.SignResponse("sig1", *hsResSigner, hsRes, hsReq)
	failIf(err, "Failed to sign fast handshake response")
	hsRes.Header.Set("Signature", sig)
	hsRes.Header.Set("Signature-Input", sigInput)

	calleePub, err := calleeKey.PublicKey()
	failIf(err, "Failed to get callee public key")
	resSigName, resDetails := verifyResponseByTag(hsRes, hsReq, calleePub, *fieldsRes, hsReqNonce)
	fmt.Printf("Verified fast handshake response %q (tag=%q, wimse-req-nonce=%q)\n",
		resSigName, *resDetails.Tag, resDetails.CustomParams["wimse-req-nonce"])

	hsResDump, err := httputil.DumpResponse(hsRes, true)
	failIf(err, "Could not dump fast handshake response")
	hsResDump = ellipsizeTicketParams(hsResDump)

	keys := deriveSessionKeys(sharedSecret, fastKemSuite, hsReqNonce, hsResNonce, callerWIT, calleeWIT)
	if debug {
		fmt.Printf("DEBUG fast: suite=%s session_id=%x\n", fastKemSuite, keys.sessionID)
	}

	// session_exp is the earlier handshake WIT exp. Callers pass expires = client WIT exp
	// and generate the server WIT with a slightly later exp, so session_exp == expires.
	sessionExp := expires

	// --- Session request (HMAC k_req; confirmation + ticket_client) ---
	rawSessReq := `GET /gimme-ice-cream?flavor=vanilla HTTP/1.1
Host: svcb.example.com

`
	sessReqFields := sessionRequestFields()
	sessReqConfig := httpsign.NewSignConfig().SetTag(fastSessionTag).
		SetNonce(sessReqNonce).SignAlg(true).SetExpires(sessionExp).
		AddCustomParam("wimse-aud", aud).
		AddCustomParam("wimse-sign-response", true).
		AddCustomParam("wimse-session-id", keys.sessionID).
		AddCustomParam("wimse-ticket-server", ticketServerPlaceholder).
		AddCustomParam("wimse-ticket-client", ticketClientPlaceholder)
	sessReqSigner, err := httpsign.NewHMACSHA256Signer(keys.kReq, sessReqConfig, *sessReqFields)
	failIf(err, "Failed to create session request signer")

	sessReq, err := http.ReadRequest(bufio.NewReader(strings.NewReader(rawSessReq)))
	failIf(err, "Failed to read session request")
	ensureContentDigest(sessReq)

	sigInput, sig, err = httpsign.SignRequest("sig1", *sessReqSigner, sessReq)
	failIf(err, "Failed to sign session request")
	sessReq.Header.Set("Signature", sig)
	sessReq.Header.Set("Signature-Input", sigInput)

	sessReqSigName, sessReqDetails := verifySessionRequest(sessReq, keys.kReq, *sessReqFields)
	fmt.Printf("Verified fast session request %q (tag=%q)\n", sessReqSigName, *sessReqDetails.Tag)

	sessReqDump, err := httputil.DumpRequest(sessReq, true)
	failIf(err, "Could not dump session request")
	sessReqDump = ellipsizeTicketParams(sessReqDump)

	// --- Session response (HMAC k_res; echo both tickets) ---
	sessResBody := "No ice cream today.\n"
	rawSessRes := fmt.Sprintf(`HTTP/1.1 404 Not Found
Content-Type: text/plain
Content-Length: %d

%s`, len(sessResBody), sessResBody)

	sessResFields := sessionResponseFields()
	// Response expires must not be after session_exp (draft {{lifetime}}).
	sessResConfig := httpsign.NewSignConfig().SetTag(fastSessionTag).
		SetNonce(sessResNonce).SignAlg(true).SetExpires(sessionExp).
		AddCustomParam("wimse-req-nonce", sessReqNonce).
		AddCustomParam("wimse-session-id", keys.sessionID).
		AddCustomParam("wimse-ticket-server", ticketServerPlaceholder).
		AddCustomParam("wimse-ticket-client", ticketClientPlaceholder)
	sessResSigner, err := httpsign.NewHMACSHA256Signer(keys.kRes, sessResConfig, *sessResFields)
	failIf(err, "Failed to create session response signer")

	sessRes, err := http.ReadResponse(bufio.NewReader(strings.NewReader(rawSessRes)), sessReq)
	failIf(err, "Failed to read session response")
	ensureResponseContentDigest(sessRes)

	sigInput, sig, err = httpsign.SignResponse("sig1", *sessResSigner, sessRes, sessReq)
	failIf(err, "Failed to sign session response")
	sessRes.Header.Set("Signature", sig)
	sessRes.Header.Set("Signature-Input", sigInput)

	sessResSigName, sessResDetails := verifySessionResponse(sessRes, sessReq, keys.kRes, *sessResFields, sessReqNonce)
	fmt.Printf("Verified fast session response %q (tag=%q, wimse-req-nonce=%q)\n",
		sessResSigName, *sessResDetails.Tag, sessResDetails.CustomParams["wimse-req-nonce"])

	sessResDump, err := httputil.DumpResponse(sessRes, true)
	failIf(err, "Could not dump session response")
	sessResDump = ellipsizeTicketParams(sessResDump)

	return fastExamples{
		hsReqDump:   hsReqDump,
		hsResDump:   hsResDump,
		sessReqDump: sessReqDump,
		sessResDump: sessResDump,
		sessionID:   keys.sessionID,
		suite:       fastKemSuite,
	}
}

func hmacEqual(a, b []byte) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}

// ellipsizeTicketParams rewrites ticket Byte Sequences in a dumped message so draft
// includes stay readable. Keep the first and last 8 base64 characters.
func ellipsizeTicketParams(dump []byte) []byte {
	return ticketParamDumpRE.ReplaceAllFunc(dump, func(m []byte) []byte {
		parts := ticketParamDumpRE.FindSubmatch(m)
		if len(parts) != 4 {
			return m
		}
		b64 := parts[2]
		if len(b64) <= 20 {
			return m
		}
		truncated := append(append(append([]byte{}, parts[1]...), b64[:8]...), []byte("...")...)
		truncated = append(truncated, b64[len(b64)-8:]...)
		truncated = append(truncated, parts[3]...)
		return truncated
	})
}
