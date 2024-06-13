package main

import (
	"bufio"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/yaronf/httpsign"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"time"
)

var request = `GET /gimme-ice-cream?flavor=vanilla HTTP/1.1
Host: example.com
Workload-Identity-Token: aGVhZGVyCg.VGhpcyBpcyBub3QgYSByZWFsIHRva2VuLgo.c2lnbmF0dXJlCg

`

var response = `HTTP/1.1 404 Not Found
Workload-Identity-Token: aGVhZGVyCg.VGhpcyBhaW4ndCBvbmUsIHRvby4K.c2lnbmF0dXJlCg
Content-Type: text/plain

No ice cream today.

`
var svcARawKey = `{
 "kty":"OKP",
 "crv":"Ed25519",
 "x":"_amRC3YrYbHhH1RtYrL8cSmTDMhYtOUTG78cGTR5ezk",
 "d":"G4lGAYFtFq5rwyjlgSIRznIoCF7MtKDHByyUUZCqLiA"
}`

var svcBRawKey = `{
 "kty":"OKP",
 "crv":"Ed25519",
 "x":"CfaY1XX-aHJpenRP8ATm3yGlbcKA_treqOfwKrilwyg",
 "d":"fycSKS-iHZ6TC1BNwN6cE0sOBP3-4KgR-eqxNpnyhws"
}`

func main() {
	svcAwitkey, err := jwk.ParseKey([]byte(svcARawKey))
	failIf(err, "Could not read key")
	created := time.Now().Unix()
	expires := created + 300
	config := httpsign.NewSignConfig().SetTag("wimse-service-to-service").
		SetNonce("abcd1111").SignAlg(false).SetExpires(expires)
	fields := httpsign.NewFields().AddHeaders("@method", "@request-target", "workload-identity-token").
		AddHeaderExt("Content-Type", true, false, false, false).
		AddHeaderExt("Content-Digest", true, false, false, false)
	signer, err := httpsign.NewJWSSigner(jwa.EdDSA, svcAwitkey, config, *fields)
	failIf(err, "Failed to create signer")
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(request)))
	failIf(err, "Failed to read request")
	signatureInput, signature, err := httpsign.SignRequest("wimse", *signer, req)
	failIf(err, "Failed to create signature")
	req.Header.Set("Signature", signature)
	req.Header.Set("Signature-Input", signatureInput)
	reqStr, err := httputil.DumpRequest(req, true)
	failIf(err, "Could not print request")
	fmt.Println("Request:\n")
	fmt.Print(string(reqStr))

	svcBwitkey, err := jwk.ParseKey([]byte(svcBRawKey))
	failIf(err, "Could not read key")
	created += 2
	expires = created + 300
	config = httpsign.NewSignConfig().SetTag("wimse-service-to-service").
		SetNonce("abcd2222").SignAlg(false).SetExpires(expires)
	fields = httpsign.NewFields().AddHeaders("@status", "workload-identity-token").
		AddHeaderExt("Content-Type", true, false, false, false).
		AddHeaderExt("Content-Digest", true, false, false, false).
		AddHeaderExt("@method", false, false, true, false).
		AddHeaderExt("@request-target", false, false, true, false)
	signer, err = httpsign.NewJWSSigner(jwa.EdDSA, svcBwitkey, config, *fields)
	failIf(err, "Failed to create signer")
	res, err := http.ReadResponse(bufio.NewReader(strings.NewReader(response)), req)
	failIf(err, "Failed to read request")

	if res.Body != nil && res.Header.Get("Content-Digest") == "" {
		header, err := httpsign.GenerateContentDigestHeader(&req.Body, []string{httpsign.DigestSha256})
		failIf(err, "Could not generate digest")
		res.Header.Set("Content-Digest", header)
	}

	signatureInput, signature, err = httpsign.SignResponse("wimse", *signer, res, req)
	failIf(err, "Failed to create signature")
	res.Header.Set("Signature", signature)
	res.Header.Set("Signature-Input", signatureInput)
	resStr, err := httputil.DumpResponse(res, true)
	failIf(err, "Could not print response")
	fmt.Println("Response:\n")
	fmt.Print(string(resStr))
}

func failIf(err error, message string) {
	if err != nil {
		fmt.Printf("%s: %s", message, err)
		os.Exit(1)
	}
}
