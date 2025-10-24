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

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/yaronf/httpsign"
)

// generateEd25519Key generates a new Ed25519 key pair and returns it as a JWK
func generateEd25519Key(keyID string) (jwk.Key, error) {
	// Generate a random Ed25519 key pair
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}

	// Convert to JWK format
	jwkKey, err := jwk.FromRaw(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert key to JWK: %w", err)
	}

	// Set the key ID
	jwkKey.Set(jwk.KeyIDKey, keyID)

	return jwkKey, nil
}

// generateWIT creates a Workload Identity Token (WIT) as specified in
// draft-ietf-wimse-s2s-protocol. A WIT is a JWT that binds a workload identity
// to a cryptographic key through the "cnf" (confirmation) claim.
//
// The WIT is signed by the issuer and contains the workload's public key in the
// cnf claim. This public key is later used to sign HTTP messages, creating a
// proof-of-possession binding between the WIT and the HTTP requests/responses.
func generateWIT(serviceKey jwk.Key, issuerKey jwk.Key, subject, issuer, serviceKeyID string, iat, exp int64, jti string) (string, error) {
	// Create the JWT token
	token := jwt.New()

	// Set standard claims
	token.Set("sub", subject)
	token.Set("iss", issuer)
	token.Set("iat", iat)
	token.Set("exp", exp)
	token.Set("jti", jti)

	// Create cnf claim with the service's public key
	// The cnf claim establishes proof-of-possession by binding the workload
	// identity to the public key that will be used for HTTP message signing
	// First, get the public key (remove private key material)
	publicKey, err := serviceKey.PublicKey()
	if err != nil {
		return "", fmt.Errorf("failed to get public key: %w", err)
	}

	// Convert to JSON
	publicKeyJSON, err := json.Marshal(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	var publicKeyMap map[string]interface{}
	if err := json.Unmarshal(publicKeyJSON, &publicKeyMap); err != nil {
		return "", fmt.Errorf("failed to unmarshal public key: %w", err)
	}

	// Add the alg field to the JWK
	publicKeyMap["alg"] = "EdDSA"

	cnf := map[string]interface{}{
		"jwk": publicKeyMap,
	}
	token.Set("cnf", cnf)

	// Sign the token with the issuer key and set the correct typ header
	// First serialize the token to JSON
	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return "", fmt.Errorf("failed to marshal token: %w", err)
	}

	// Create headers with the correct typ
	headers := jws.NewHeaders()
	if err := headers.Set("typ", "wit+jwt"); err != nil {
		return "", fmt.Errorf("failed to set typ header: %w", err)
	}
	if err := headers.Set("alg", "EdDSA"); err != nil {
		return "", fmt.Errorf("failed to set alg header: %w", err)
	}
	if err := headers.Set("kid", "issuer-key"); err != nil {
		return "", fmt.Errorf("failed to set kid header: %w", err)
	}

	// Sign using jws.Sign directly
	signed, err := jws.Sign(tokenJSON, jws.WithKey(jwa.EdDSA, issuerKey, jws.WithProtectedHeaders(headers)))
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

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		fmt.Printf("Error decoding header: %v\n", err)
		return
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		fmt.Printf("Error parsing header: %v\n", err)
		return
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		fmt.Printf("Error decoding payload: %v\n", err)
		return
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		fmt.Printf("Error parsing payload: %v\n", err)
		return
	}

	fmt.Println("Header:")
	prettyPrint(header)

	fmt.Println("\nPayload:")
	prettyPrint(payload)
}

func prettyPrint(data map[string]interface{}) {
	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Printf("Error pretty printing: %v\n", err)
		return
	}
	fmt.Println(string(jsonBytes))
}

func jwkToString(key jwk.Key) (string, error) {
	// Convert the complete key (including private key material) to JSON
	jsonBytes, err := json.MarshalIndent(key, "", "  ")
	if err != nil {
		return "", fmt.Errorf("error marshaling JWK: %w", err)
	}

	// Parse the JSON to add the alg field
	var keyMap map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &keyMap); err != nil {
		return "", fmt.Errorf("error unmarshaling JWK: %w", err)
	}

	// Add the alg field
	keyMap["alg"] = "EdDSA"

	// Marshal back to JSON
	finalJSON, err := json.MarshalIndent(keyMap, "", "  ")
	if err != nil {
		return "", fmt.Errorf("error marshaling final JWK: %w", err)
	}

	return string(finalJSON), nil
}

func printJWK(key jwk.Key) {
	jwkStr, err := jwkToString(key)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	fmt.Println(jwkStr)
}

func writeToFile(filename, content string) error {
	return os.WriteFile(filename, []byte(content), 0644)
}

func main() {
	// Parse command line flags
	debugFlag := flag.Bool("debug", false, "Enable debug mode to decode WIT tokens")
	stdoutFlag := flag.Bool("stdout", false, "Print output to stdout instead of files")
	flag.Parse()

	// Generate all keys dynamically
	svcAKey, err := generateEd25519Key("svc-a-key")
	failIf(err, "Could not generate service A key")

	svcBKey, err := generateEd25519Key("svc-b-key")
	failIf(err, "Could not generate service B key")

	issuerKey, err := generateEd25519Key("issuer-key")
	failIf(err, "Could not generate issuer key")

	// Generate timestamps
	now := time.Now().Unix()
	expires := now + 300

	// Generate WITs
	svcAWIT, err := generateWIT(svcAKey, issuerKey, "wimse://example.com/svcA", "https://example.com/issuer", "svc-a-key", now, expires, fmt.Sprintf("wit-%d", time.Now().UnixNano()))
	failIf(err, "Failed to generate service A WIT")

	svcBWIT, err := generateWIT(svcBKey, issuerKey, "wimse://example.com/svcB", "https://example.com/issuer", "svc-b-key", now+2, expires+2, fmt.Sprintf("wit-%d", time.Now().UnixNano()))
	failIf(err, "Failed to generate service B WIT")

	// Create request with service A WIT
	request := fmt.Sprintf(`GET /gimme-ice-cream?flavor=vanilla HTTP/1.1
Host: example.com
Workload-Identity-Token: %s

`, svcAWIT)

	// Create response with service B WIT
	response := fmt.Sprintf(`HTTP/1.1 404 Not Found
Workload-Identity-Token: %s
Content-Type: text/plain

No ice cream today.

`, svcBWIT)

	// Sign the request with service A key
	// This implements the HTTP Message Signatures specification from draft-ietf-wimse-http-signature
	// which is based on RFC 9421 with WIMSE-specific extensions:
	// - Uses "wimse-workload-to-workload" signature tag
	// - Signs the Workload-Identity-Token header to bind the WIT to the message
	// - Uses JWS format with Ed25519 (EdDSA) algorithm
	config := httpsign.NewSignConfig().SetTag("wimse-workload-to-workload").
		SetNonce("abcd1111").SignAlg(false).SetExpires(expires)
	fields := httpsign.NewFields().AddHeaders("@method", "@request-target", "workload-identity-token").
		AddHeaderExt("Content-Type", true, false, false, false).
		AddHeaderExt("Content-Digest", true, false, false, false)
	signer, err := httpsign.NewJWSSigner(jwa.EdDSA, svcAKey, config, *fields)
	failIf(err, "Failed to create request signer")

	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(request)))
	failIf(err, "Failed to read request")

	signatureInput, signature, err := httpsign.SignRequest("wimse", *signer, req)
	failIf(err, "Failed to create request signature")
	req.Header.Set("Signature", signature)
	req.Header.Set("Signature-Input", signatureInput)

	reqStr, err := httputil.DumpRequest(req, true)
	failIf(err, "Could not print request")

	// Sign the response with service B key
	// Response signatures per draft-ietf-wimse-http-signature include:
	// - The @status derived component
	// - The Workload-Identity-Token header from the response
	// - Request components (@method, @request-target) for binding response to request
	config = httpsign.NewSignConfig().SetTag("wimse-workload-to-workload").
		SetNonce("abcd2222").SignAlg(false).SetExpires(expires + 2)
	fields = httpsign.NewFields().AddHeaders("@status", "workload-identity-token").
		AddHeaderExt("Content-Type", true, false, false, false).
		AddHeaderExt("Content-Digest", true, false, false, false).
		AddHeaderExt("@method", false, false, true, false).
		AddHeaderExt("@request-target", false, false, true, false)
	signer, err = httpsign.NewJWSSigner(jwa.EdDSA, svcBKey, config, *fields)
	failIf(err, "Failed to create response signer")

	res, err := http.ReadResponse(bufio.NewReader(strings.NewReader(response)), req)
	failIf(err, "Failed to read response")

	if res.Body != nil && res.Header.Get("Content-Digest") == "" {
		header, err := httpsign.GenerateContentDigestHeader(&req.Body, []string{httpsign.DigestSha256})
		failIf(err, "Could not generate digest")
		res.Header.Set("Content-Digest", header)
	}

	signatureInput, signature, err = httpsign.SignResponse("wimse", *signer, res, req)
	failIf(err, "Failed to create response signature")
	res.Header.Set("Signature", signature)
	res.Header.Set("Signature-Input", signatureInput)

	resStr, err := httputil.DumpResponse(res, true)
	failIf(err, "Could not print response")

	// Get JWK strings
	svcAJWK, err := jwkToString(svcAKey)
	failIf(err, "Failed to convert Service A JWK to string")

	svcBJWK, err := jwkToString(svcBKey)
	failIf(err, "Failed to convert Service B JWK to string")

	// Output to stdout or files based on flag
	if *stdoutFlag {
		// Print to stdout
		fmt.Println("Request:")
		fmt.Print(string(reqStr))

		fmt.Println("Response:")
		fmt.Print(string(resStr))

		// Debug mode: decode the WIT tokens
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

		// Print Service A JWK
		fmt.Println()
		fmt.Println("Service A JWK")
		fmt.Println(svcAJWK)

		// Print Service B JWK for figure 15
		fmt.Println()
		fmt.Println("Service B JWK (Figure 15)")
		fmt.Println(svcBJWK)
	} else {
		// Write to files in "out" directory
		// Create "out" directory if it doesn't exist
		err := os.MkdirAll("out", 0755)
		failIf(err, "Failed to create 'out' directory")

		// Write to files
		err = writeToFile("out/sigs-request.txt.out", string(reqStr))
		failIf(err, "Failed to write request to file")

		err = writeToFile("out/sigs-response.txt.out", string(resStr))
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
		fmt.Printf("%s: %s", message, err)
		os.Exit(1)
	}
}
