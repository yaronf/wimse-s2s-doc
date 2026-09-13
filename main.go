package main

// This program generates examples for the WIMSE HTTP Signatures specification
// (draft-ietf-wimse-http-signature) and the WIMSE Service-to-Service Protocol
// (draft-ietf-wimse-s2s-protocol).
//
// The HTTP signatures are based on RFC 9421 (HTTP Message Signatures) with
// WIMSE-specific extensions including:
// - The "wimse-workload-to-workload" signature tag
// - Signing of Workload-Identity-Token headers
// - Use of JWS-based signatures with Ed25519 keys

import (
	"bufio"
	"crypto/ed25519"
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

// generateEd25519Key generates a new Ed25519 key pair and returns it as a JWK
func generateEd25519Key(keyID string) (jwk.Key, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}

	jwkKey, err := jwk.Import[jwk.Key](privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert key to JWK: %w", err)
	}

	if err := jwkKey.Set(jwk.KeyIDKey, keyID); err != nil {
		return nil, fmt.Errorf("failed to set kid: %w", err)
	}
	if err := jwkKey.Set(jwk.AlgorithmKey, jwa.EdDSA()); err != nil {
		return nil, fmt.Errorf("failed to set alg: %w", err)
	}

	return jwkKey, nil
}

// generateWIT creates a Workload Identity Token (WIT) as specified in
// draft-ietf-wimse-s2s-protocol. A WIT is a JWT that binds a workload identity
// to a cryptographic key through the "cnf" (confirmation) claim.
func generateWIT(serviceKey jwk.Key, issuerKey jwk.Key, issuerKeyID, subject, issuer string, iat, exp int64, jti string) (string, error) {
	token, err := jwt.NewBuilder().
		Subject(subject).
		Issuer(issuer).
		IssuedAt(time.Unix(iat, 0)).
		Expiration(time.Unix(exp, 0)).
		JwtID(jti).
		Build()
	if err != nil {
		return "", fmt.Errorf("failed to build WIT claims: %w", err)
	}

	publicKey, err := serviceKey.PublicKey()
	if err != nil {
		return "", fmt.Errorf("failed to get public key: %w", err)
	}

	publicKeyJSON, err := json.Marshal(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	var publicKeyMap map[string]any
	if err := json.Unmarshal(publicKeyJSON, &publicKeyMap); err != nil {
		return "", fmt.Errorf("failed to unmarshal public key: %w", err)
	}

	if err := token.Set("cnf", map[string]any{"jwk": publicKeyMap}); err != nil {
		return "", fmt.Errorf("failed to set cnf claim: %w", err)
	}

	headers := jws.NewHeaders()
	if err := headers.Set(jws.TypeKey, "wit+jwt"); err != nil {
		return "", fmt.Errorf("failed to set typ header: %w", err)
	}
	if err := headers.Set(jws.KeyIDKey, issuerKeyID); err != nil {
		return "", fmt.Errorf("failed to set kid header: %w", err)
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.EdDSA(), issuerKey, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return "", fmt.Errorf("failed to sign WIT: %w", err)
	}

	return string(signed), nil
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

func jwkToString(key jwk.Key) (string, error) {
	jsonBytes, err := json.MarshalIndent(key, "", "  ")
	if err != nil {
		return "", fmt.Errorf("error marshaling JWK: %w", err)
	}
	return string(jsonBytes), nil
}

func writeToFile(filename, content string) error {
	return os.WriteFile(filename, []byte(content), 0644)
}

const wimseTag = "wimse-workload-to-workload"

func verifyRequestByTag(req *http.Request, pubKey jwk.Key, fields httpsign.Fields) (string, *httpsign.MessageDetails, error) {
	details, err := httpsign.RequestDetailsByTag(req, wimseTag)
	if err != nil {
		return "", nil, err
	}

	allowed, err := httpsign.NewJWSAlgAllowlist(jwa.EdDSA())
	if err != nil {
		return "", nil, err
	}
	vconfig := httpsign.NewVerifyConfig().SetAllowedTags([]string{wimseTag})
	verifier, err := httpsign.NewJWSVerifier(allowed, pubKey, vconfig, fields)
	if err != nil {
		return "", nil, err
	}
	if err := httpsign.VerifyRequest(details.Label, *verifier, req); err != nil {
		return "", nil, err
	}
	return details.Label, details, nil
}

func verifyResponseByTag(res *http.Response, req *http.Request, pubKey jwk.Key, fields httpsign.Fields, wantReqNonce string) (string, *httpsign.MessageDetails, error) {
	details, err := httpsign.ResponseDetailsByTag(res, wimseTag)
	if err != nil {
		return "", nil, err
	}

	allowed, err := httpsign.NewJWSAlgAllowlist(jwa.EdDSA())
	if err != nil {
		return "", nil, err
	}
	vconfig := httpsign.NewVerifyConfig().SetAllowedTags([]string{wimseTag})
	verifier, err := httpsign.NewJWSVerifier(allowed, pubKey, vconfig, fields)
	if err != nil {
		return "", nil, err
	}
	if err := httpsign.VerifyResponse(details.Label, *verifier, res, req); err != nil {
		return "", nil, err
	}
	got, ok := details.CustomParams["wimse-req-nonce"].(string)
	if !ok || got != wantReqNonce {
		return "", nil, fmt.Errorf("wimse-req-nonce mismatch: got %v, want %q", details.CustomParams["wimse-req-nonce"], wantReqNonce)
	}
	return details.Label, details, nil
}

func main() {
	debugFlag := flag.Bool("debug", false, "Enable debug mode to decode WIT tokens")
	stdoutFlag := flag.Bool("stdout", false, "Print output to stdout instead of files")
	flag.Parse()

	svcAKey, err := generateEd25519Key("svc-a-key")
	failIf(err, "Could not generate service A key")

	svcBKey, err := generateEd25519Key("svc-b-key")
	failIf(err, "Could not generate service B key")

	issuerKey, err := generateEd25519Key("issuer-key")
	failIf(err, "Could not generate issuer key")

	now := time.Now().Unix()
	expires := now + 300

	svcAWIT, err := generateWIT(svcAKey, issuerKey, "issuer-key", "wimse://example.com/svcA", "https://example.com/issuer", now, expires, fmt.Sprintf("wit-%d", time.Now().UnixNano()))
	failIf(err, "Failed to generate service A WIT")

	svcBWIT, err := generateWIT(svcBKey, issuerKey, "issuer-key", "wimse://example.com/svcB", "https://example.com/issuer", now+2, expires+2, fmt.Sprintf("wit-%d", time.Now().UnixNano()))
	failIf(err, "Failed to generate service B WIT")

	request := fmt.Sprintf(`GET /gimme-ice-cream?flavor=vanilla HTTP/1.1
Host: svcb.example.com
Workload-Identity-Token: %s

`, svcAWIT)

	response := fmt.Sprintf(`HTTP/1.1 404 Not Found
Workload-Identity-Token: %s
Content-Type: text/plain

No ice cream today.

`, svcBWIT)

	reqNonce := "abcd1111"
	config := httpsign.NewSignConfig().SetTag(wimseTag).
		SetNonce(reqNonce).SignAlg(false).SetExpires(expires).
		AddCustomParam("wimse-aud", "https://svcb.example.com/gimme-ice-cream").
		AddCustomParam("wimse-sign-response", true)
	fields := httpsign.NewFields().AddHeaders("@method", "@path", "@query", "workload-identity-token").
		AddHeaderOptional("Content-Type").
		AddHeaderOptional("Content-Digest")
	signer, err := httpsign.NewJWSSignerFromJWK(svcAKey, config, *fields)
	failIf(err, "Failed to create request signer")

	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(request)))
	failIf(err, "Failed to read request")

	signatureInput, signature, err := httpsign.SignRequest("sig1", *signer, req)
	failIf(err, "Failed to create request signature")
	req.Header.Set("Signature", signature)
	req.Header.Set("Signature-Input", signatureInput)

	svcAPub, err := svcAKey.PublicKey()
	failIf(err, "Failed to get service A public key")
	reqSigName, reqDetails, err := verifyRequestByTag(req, svcAPub, *fields)
	failIf(err, "Failed to verify request signature")
	fmt.Printf("Verified request signature %q (tag=%q)\n", reqSigName, *reqDetails.Tag)

	reqStr, err := httputil.DumpRequest(req, true)
	failIf(err, "Could not print request")

	config = httpsign.NewSignConfig().SetTag(wimseTag).
		SetNonce("abcd2222").SignAlg(false).SetExpires(expires + 2).
		AddCustomParam("wimse-req-nonce", reqNonce)
	fields = httpsign.NewFields().AddHeaders("@status", "workload-identity-token").
		AddHeaderOptional("Content-Type").
		AddHeaderOptional("Content-Digest").
		AddRequestComponent("@method").
		AddRequestComponent("@path").
		AddRequestComponent("@query")
	signer, err = httpsign.NewJWSSignerFromJWK(svcBKey, config, *fields)
	failIf(err, "Failed to create response signer")

	res, err := http.ReadResponse(bufio.NewReader(strings.NewReader(response)), req)
	failIf(err, "Failed to read response")

	if res.Body != nil && res.Header.Get("Content-Digest") == "" {
		header, err := httpsign.GenerateContentDigestHeader(&res.Body, []string{httpsign.DigestSha256})
		failIf(err, "Could not generate digest")
		res.Header.Set("Content-Digest", header)
	}

	signatureInput, signature, err = httpsign.SignResponse("sig1", *signer, res, req)
	failIf(err, "Failed to create response signature")
	res.Header.Set("Signature", signature)
	res.Header.Set("Signature-Input", signatureInput)

	svcBPub, err := svcBKey.PublicKey()
	failIf(err, "Failed to get service B public key")
	resSigName, resDetails, err := verifyResponseByTag(res, req, svcBPub, *fields, reqNonce)
	failIf(err, "Failed to verify response signature")
	fmt.Printf("Verified response signature %q (tag=%q, wimse-req-nonce=%q)\n",
		resSigName, *resDetails.Tag, resDetails.CustomParams["wimse-req-nonce"])

	resStr, err := httputil.DumpResponse(res, true)
	failIf(err, "Could not print response")

	svcAJWK, err := jwkToString(svcAKey)
	failIf(err, "Failed to convert Service A JWK to string")

	svcBJWK, err := jwkToString(svcBKey)
	failIf(err, "Failed to convert Service B JWK to string")

	if *stdoutFlag {
		fmt.Println("Request:")
		fmt.Print(string(reqStr))

		fmt.Println("Response:")
		fmt.Print(string(resStr))

		if *debugFlag {
			fmt.Println()
			fmt.Println("DEBUG: Decoding WIT tokens")
			fmt.Println()

			fmt.Println("=== Service A WIT ===")
			decodeJWT(svcAWIT)

			fmt.Println()
			fmt.Println("=== Service B WIT ===")
			decodeJWT(svcBWIT)
		}

		fmt.Println()
		fmt.Println("Service A JWK")
		fmt.Println(svcAJWK)

		fmt.Println()
		fmt.Println("Service B JWK (Figure 15)")
		fmt.Println(svcBJWK)
	} else {
		err := os.MkdirAll("out", 0755)
		failIf(err, "Failed to create 'out' directory")

		err = writeToFile("out/sigs-request.txt", string(reqStr))
		failIf(err, "Failed to write request to file")

		err = writeToFile("out/sigs-response.txt", string(resStr))
		failIf(err, "Failed to write response to file")

		err = writeToFile("out/sigs-svca-jwk.txt", svcAJWK+"\n")
		failIf(err, "Failed to write Service A JWK to file")

		err = writeToFile("out/sigs-svcb-jwk.txt", svcBJWK+"\n")
		failIf(err, "Failed to write Service B JWK to file")

		fmt.Println("Output written to files in 'out' directory")
	}
}

func failIf(err error, message string) {
	if err != nil {
		fmt.Printf("%s: %s\n", message, err)
		os.Exit(1)
	}
}
