package main

// This program generates examples for the WIMSE HTTP Signatures specification
// (draft-ietf-wimse-http-signature) and the WIMSE Service-to-Service Protocol
// (draft-ietf-wimse-s2s-protocol).
//
// The HTTP signatures are based on RFC 9421 (HTTP Message Signatures) with
// WIMSE-specific extensions including:
// - The "wimse-workload-to-workload" signature tag
// - Signing of Workload-Identity-Token headers
// - JWS-based signatures with Ed25519 and ES256 keys (RFC 9864 alg names)

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/yaronf/httpsign"
)

const wimseTag = "wimse-workload-to-workload"

func generateEd25519Key(keyID string) jwk.Key {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	failIf(err, "Failed to generate Ed25519 key")

	jwkKey, err := jwk.Import[jwk.Key](privateKey)
	failIf(err, "Failed to convert Ed25519 key to JWK")

	failIf(jwkKey.Set(jwk.KeyIDKey, keyID), "Failed to set kid")
	// RFC 9864: use "Ed25519" rather than legacy "EdDSA"
	failIf(jwkKey.Set(jwk.AlgorithmKey, jwa.EdDSAEd25519()), "Failed to set alg")

	return jwkKey
}

func generateES256Key(keyID string) jwk.Key {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	failIf(err, "Failed to generate P-256 key")

	jwkKey, err := jwk.Import[jwk.Key](privateKey)
	failIf(err, "Failed to convert P-256 key to JWK")

	failIf(jwkKey.Set(jwk.KeyIDKey, keyID), "Failed to set kid")
	failIf(jwkKey.Set(jwk.AlgorithmKey, jwa.ES256()), "Failed to set alg")

	return jwkKey
}

// generateWIT creates a Workload Identity Token (WIT): a JWT that binds a
// workload identity to a cryptographic key through the "cnf" claim.
// The issuer always signs with Ed25519; the PoP key in cnf.jwk may be Ed25519 or ES256.
func generateWIT(serviceKey jwk.Key, issuerKey jwk.Key, issuerKeyID, subject, issuer string, iat, exp int64, jti string) string {
	token, err := jwt.NewBuilder().
		Subject(subject).
		Issuer(issuer).
		IssuedAt(time.Unix(iat, 0)).
		Expiration(time.Unix(exp, 0)).
		JwtID(jti).
		Build()
	failIf(err, "Failed to build WIT claims")

	publicKey, err := serviceKey.PublicKey()
	failIf(err, "Failed to get public key")

	publicKeyJSON, err := json.Marshal(publicKey)
	failIf(err, "Failed to marshal public key")

	var publicKeyMap map[string]any
	failIf(json.Unmarshal(publicKeyJSON, &publicKeyMap), "Failed to unmarshal public key")

	failIf(token.Set("cnf", map[string]any{"jwk": publicKeyMap}), "Failed to set cnf claim")

	headers := jws.NewHeaders()
	failIf(headers.Set(jws.TypeKey, "wit+jwt"), "Failed to set typ header")
	failIf(headers.Set(jws.KeyIDKey, issuerKeyID), "Failed to set kid header")

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.EdDSAEd25519(), issuerKey, jws.WithProtectedHeaders(headers)))
	failIf(err, "Failed to sign WIT")

	return string(signed)
}

func decodeJWT(token string) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		fmt.Println("Invalid JWT format")
		return
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		fmt.Printf("Error decoding header: %v\n", err)
		return
	}

	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		fmt.Printf("Error parsing header: %v\n", err)
		return
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		fmt.Printf("Error decoding payload: %v\n", err)
		return
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		fmt.Printf("Error parsing payload: %v\n", err)
		return
	}

	fmt.Println("Header:")
	prettyPrint(header)

	fmt.Println("\nPayload:")
	prettyPrint(payload)
}

func prettyPrint(data map[string]any) {
	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Printf("Error pretty printing: %v\n", err)
		return
	}
	fmt.Println(string(jsonBytes))
}

func jwkToString(key jwk.Key) string {
	jsonBytes, err := json.MarshalIndent(key, "", "  ")
	failIf(err, "Failed to marshal JWK")
	return string(jsonBytes)
}

func writeToFile(filename, content string) error {
	return os.WriteFile(filename, []byte(content), 0644)
}

func jwsAllowlist() *httpsign.JWSAlgAllowlist {
	allowed, err := httpsign.NewJWSAlgAllowlist(jwa.EdDSAEd25519(), jwa.ES256())
	failIf(err, "Failed to create JWS algorithm allowlist")
	return allowed
}

func verifyRequestByTag(req *http.Request, pubKey jwk.Key, fields httpsign.Fields) (string, *httpsign.MessageDetails) {
	details, err := httpsign.RequestDetailsByTag(req, wimseTag)
	failIf(err, "Failed to get request signature details by tag")

	vconfig := httpsign.NewVerifyConfig().SetAllowedTags([]string{wimseTag})
	verifier, err := httpsign.NewJWSVerifier(jwsAllowlist(), pubKey, vconfig, fields)
	failIf(err, "Failed to create request verifier")
	failIf(httpsign.VerifyRequest(details.Label, *verifier, req), "Failed to verify request signature")
	return details.Label, details
}

func verifyResponseByTag(res *http.Response, req *http.Request, pubKey jwk.Key, fields httpsign.Fields, wantReqNonce string) (string, *httpsign.MessageDetails) {
	details, err := httpsign.ResponseDetailsByTag(res, wimseTag)
	failIf(err, "Failed to get response signature details by tag")

	vconfig := httpsign.NewVerifyConfig().SetAllowedTags([]string{wimseTag})
	verifier, err := httpsign.NewJWSVerifier(jwsAllowlist(), pubKey, vconfig, fields)
	failIf(err, "Failed to create response verifier")
	failIf(httpsign.VerifyResponse(details.Label, *verifier, res, req), "Failed to verify response signature")
	got, ok := details.CustomParams["wimse-req-nonce"].(string)
	if !ok || got != wantReqNonce {
		failIf(fmt.Errorf("got %v, want %q", details.CustomParams["wimse-req-nonce"], wantReqNonce), "wimse-req-nonce mismatch")
	}
	return details.Label, details
}

func ensureContentDigest(req *http.Request) {
	if req.Body == nil || req.Body == http.NoBody || req.ContentLength == 0 || req.Header.Get("Content-Digest") != "" {
		return
	}
	header, err := httpsign.GenerateContentDigestHeader(&req.Body, []string{httpsign.DigestSha256})
	failIf(err, "Could not generate request Content-Digest")
	req.Header.Set("Content-Digest", header)
}

func ensureResponseContentDigest(res *http.Response) {
	if res.Body == nil || res.Body == http.NoBody || res.ContentLength == 0 || res.Header.Get("Content-Digest") != "" {
		return
	}
	header, err := httpsign.GenerateContentDigestHeader(&res.Body, []string{httpsign.DigestSha256})
	failIf(err, "Could not generate response Content-Digest")
	res.Header.Set("Content-Digest", header)
}

func requestFields() *httpsign.Fields {
	return httpsign.NewFields().
		AddHeaders("@method", "@path", "@query", "workload-identity-token").
		AddHeaderOptional("Content-Type").
		AddHeaderOptional("Content-Digest")
}

func responseFields() *httpsign.Fields {
	return httpsign.NewFields().
		AddHeaders("@status", "workload-identity-token").
		AddHeaderOptional("Content-Type").
		AddHeaderOptional("Content-Digest").
		AddRequestComponent("@method").
		AddRequestComponent("@path").
		AddRequestComponent("@query")
}

type signedExchange struct {
	reqDump []byte
	resDump []byte
}

func signExchange(
	rawReq, rawRes string,
	callerKey, calleeKey jwk.Key,
	aud, reqNonce, resNonce string,
	expires int64,
) signedExchange {
	fieldsReq := requestFields()
	config := httpsign.NewSignConfig().SetTag(wimseTag).
		SetNonce(reqNonce).SignAlg(false).SetExpires(expires).
		AddCustomParam("wimse-aud", aud).
		AddCustomParam("wimse-sign-response", true)
	signer, err := httpsign.NewJWSSignerFromJWK(callerKey, config, *fieldsReq)
	failIf(err, "Failed to create request signer")

	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(rawReq)))
	failIf(err, "Failed to read request")
	ensureContentDigest(req)

	signatureInput, signature, err := httpsign.SignRequest("sig1", *signer, req)
	failIf(err, "Failed to create request signature")
	req.Header.Set("Signature", signature)
	req.Header.Set("Signature-Input", signatureInput)

	callerPub, err := callerKey.PublicKey()
	failIf(err, "Failed to get caller public key")
	reqSigName, reqDetails := verifyRequestByTag(req, callerPub, *fieldsReq)
	fmt.Printf("Verified request signature %q (tag=%q)\n", reqSigName, *reqDetails.Tag)

	reqStr, err := httputil.DumpRequest(req, true)
	failIf(err, "Could not print request")

	fieldsRes := responseFields()
	config = httpsign.NewSignConfig().SetTag(wimseTag).
		SetNonce(resNonce).SignAlg(false).SetExpires(expires + 2).
		AddCustomParam("wimse-req-nonce", reqNonce)
	signer, err = httpsign.NewJWSSignerFromJWK(calleeKey, config, *fieldsRes)
	failIf(err, "Failed to create response signer")

	res, err := http.ReadResponse(bufio.NewReader(strings.NewReader(rawRes)), req)
	failIf(err, "Failed to read response")
	ensureResponseContentDigest(res)

	signatureInput, signature, err = httpsign.SignResponse("sig1", *signer, res, req)
	failIf(err, "Failed to create response signature")
	res.Header.Set("Signature", signature)
	res.Header.Set("Signature-Input", signatureInput)

	calleePub, err := calleeKey.PublicKey()
	failIf(err, "Failed to get callee public key")
	resSigName, resDetails := verifyResponseByTag(res, req, calleePub, *fieldsRes, reqNonce)
	fmt.Printf("Verified response signature %q (tag=%q, wimse-req-nonce=%q)\n",
		resSigName, *resDetails.Tag, resDetails.CustomParams["wimse-req-nonce"])

	resStr, err := httputil.DumpResponse(res, true)
	failIf(err, "Could not print response")

	return signedExchange{reqDump: reqStr, resDump: resStr}
}

func main() {
	debugFlag := flag.Bool("debug", false, "Enable debug mode to decode WIT tokens")
	stdoutFlag := flag.Bool("stdout", false, "Print output to stdout instead of files")
	flag.Parse()

	svcAKey := generateEd25519Key("svc-a-key")
	svcBKey := generateEd25519Key("svc-b-key")
	svcCKey := generateES256Key("svc-c-key")
	issuerKey := generateEd25519Key("issuer-key")

	now := time.Now().Unix()
	expires := now + 300

	svcAWIT := generateWIT(svcAKey, issuerKey, "issuer-key", "wimse://example.com/svcA", "https://example.com/issuer", now, expires, fmt.Sprintf("wit-%d", time.Now().UnixNano()))
	svcBWIT := generateWIT(svcBKey, issuerKey, "issuer-key", "wimse://example.com/svcB", "https://example.com/issuer", now+2, expires+2, fmt.Sprintf("wit-%d", time.Now().UnixNano()))
	svcCWIT := generateWIT(svcCKey, issuerKey, "issuer-key", "wimse://example.com/svcC", "https://example.com/issuer", now+4, expires+4, fmt.Sprintf("wit-%d", time.Now().UnixNano()))

	// Ed25519: svcA → svcB (GET, no body)
	abReq := fmt.Sprintf(`GET /gimme-ice-cream?flavor=vanilla HTTP/1.1
Host: svcb.example.com
Workload-Identity-Token: %s

`, svcAWIT)

	abResBody := "No ice cream today.\n"
	abRes := fmt.Sprintf(`HTTP/1.1 404 Not Found
Workload-Identity-Token: %s
Content-Type: text/plain
Content-Length: %d

%s`, svcBWIT, len(abResBody), abResBody)

	fmt.Println("=== Ed25519: svcA → svcB ===")
	ab := signExchange(abReq, abRes, svcAKey, svcBKey,
		"https://svcb.example.com/gimme-ice-cream", "abcd1111", "abcd2222", expires)

	// ES256: svcB → svcC (POST deducts one cone; body → Content-Digest on request)
	bcReqBody := `{"flavor":"vanilla","amount":1}`
	bcReq := fmt.Sprintf(`POST /inventory/cones HTTP/1.1
Host: svcc.example.com
Content-Type: application/json
Content-Length: %d
Workload-Identity-Token: %s

%s`, len(bcReqBody), svcBWIT, bcReqBody)

	bcResBody := `{"error":"out_of_stock","flavor":"vanilla"}`
	bcRes := fmt.Sprintf(`HTTP/1.1 409 Conflict
Workload-Identity-Token: %s
Content-Type: application/json
Content-Length: %d

%s`, svcCWIT, len(bcResBody), bcResBody)

	fmt.Println("=== ES256: svcB → svcC ===")
	bc := signExchange(bcReq, bcRes, svcBKey, svcCKey,
		"https://svcc.example.com/inventory/cones", "abcd3333", "abcd4444", expires+4)

	svcAJWK := jwkToString(svcAKey)
	svcBJWK := jwkToString(svcBKey)
	svcCJWK := jwkToString(svcCKey)

	if *stdoutFlag {
		fmt.Println("Request (svcA → svcB):")
		fmt.Print(string(ab.reqDump))
		fmt.Println("Response (svcB → svcA):")
		fmt.Print(string(ab.resDump))
		fmt.Println("Request (svcB → svcC):")
		fmt.Print(string(bc.reqDump))
		fmt.Println("Response (svcC → svcB):")
		fmt.Print(string(bc.resDump))

		if *debugFlag {
			fmt.Println()
			fmt.Println("DEBUG: Decoding WIT tokens")
			fmt.Println()
			fmt.Println("=== Service A WIT ===")
			decodeJWT(svcAWIT)
			fmt.Println()
			fmt.Println("=== Service B WIT ===")
			decodeJWT(svcBWIT)
			fmt.Println()
			fmt.Println("=== Service C WIT ===")
			decodeJWT(svcCWIT)
		}

		fmt.Println()
		fmt.Println("Service A JWK")
		fmt.Println(svcAJWK)
		fmt.Println()
		fmt.Println("Service B JWK")
		fmt.Println(svcBJWK)
		fmt.Println()
		fmt.Println("Service C JWK")
		fmt.Println(svcCJWK)
	} else {
		err := os.MkdirAll("out", 0755)
		failIf(err, "Failed to create 'out' directory")

		failIf(writeToFile("out/sigs-request.txt", string(ab.reqDump)), "Failed to write A→B request")
		failIf(writeToFile("out/sigs-response.txt", string(ab.resDump)), "Failed to write A→B response")
		failIf(writeToFile("out/sigs-request-b-c.txt", string(bc.reqDump)), "Failed to write B→C request")
		failIf(writeToFile("out/sigs-response-c.txt", string(bc.resDump)), "Failed to write B→C response")
		failIf(writeToFile("out/sigs-svca-jwk.txt", svcAJWK+"\n"), "Failed to write Service A JWK")
		failIf(writeToFile("out/sigs-svcb-jwk.txt", svcBJWK+"\n"), "Failed to write Service B JWK")
		failIf(writeToFile("out/sigs-svcc-jwk.txt", svcCJWK+"\n"), "Failed to write Service C JWK")

		fmt.Println("Output written to files in 'out' directory")
	}
}

func failIf(err error, message string) {
	if err != nil {
		fmt.Printf("%s: %s\n", message, err)
		os.Exit(1)
	}
}
