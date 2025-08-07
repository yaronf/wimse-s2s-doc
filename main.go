package main

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
	if err := headers.Set("typ", "wimse-id+jwt"); err != nil {
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

func printJWK(key jwk.Key) {
	// Convert the complete key (including private key material) to JSON
	jsonBytes, err := json.MarshalIndent(key, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling JWK: %v\n", err)
		return
	}
	
	// Parse the JSON to add the alg field
	var keyMap map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &keyMap); err != nil {
		fmt.Printf("Error unmarshaling JWK: %v\n", err)
		return
	}
	
	// Add the alg field
	keyMap["alg"] = "EdDSA"
	
	// Marshal back to JSON
	finalJSON, err := json.MarshalIndent(keyMap, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling final JWK: %v\n", err)
		return
	}

	fmt.Println(string(finalJSON))
}

func main() {
	// Parse command line flags
	debugFlag := flag.Bool("debug", false, "Enable debug mode to decode WIT tokens")
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
	fmt.Println("Request:\n")
	fmt.Print(string(reqStr))

	// Sign the response with service B key
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
	fmt.Println("Response:\n")
	fmt.Print(string(resStr))

	// Debug mode: decode the WIT tokens
	if *debugFlag {
		fmt.Println("\n" + strings.Repeat("=", 80))
		fmt.Println("DEBUG: Decoding WIT tokens")
		fmt.Println(strings.Repeat("=", 80))

		fmt.Println("\n=== Service A WIT ===")
		decodeJWT(svcAWIT)

		fmt.Println("\n=== Service B WIT ===")
		decodeJWT(svcBWIT)
	}

	// Print Service B JWK for figure 15
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("Service B JWK (Figure 15)")
	fmt.Println(strings.Repeat("=", 80))
	printJWK(svcBKey)
}

func failIf(err error, message string) {
	if err != nil {
		fmt.Printf("%s: %s", message, err)
		os.Exit(1)
	}
}
