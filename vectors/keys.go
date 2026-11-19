package vectors

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"reflect"
	"unsafe"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/yaronf/httpsign"
)

// Keyring holds parsed public/private keys for the vector set.
type Keyring struct {
	IssuerPub jwk.Key
	Issuer    jwk.Key
	SvcA      jwk.Key
	SvcAPub   jwk.Key
	SvcB      jwk.Key
	SvcBPub   jwk.Key
	SvcC      jwk.Key
	SvcCPub   jwk.Key
	Other     jwk.Key
	OtherPub  jwk.Key
}

func LoadKeyring(vs *VectorSet) (*Keyring, error) {
	kr := &Keyring{}
	var err error
	if kr.Issuer, kr.IssuerPub, err = materialToKeys(vs.Keys["issuer"]); err != nil {
		return nil, fmt.Errorf("issuer: %w", err)
	}
	if kr.SvcA, kr.SvcAPub, err = materialToKeys(vs.Keys["svcA"]); err != nil {
		return nil, fmt.Errorf("svcA: %w", err)
	}
	if kr.SvcB, kr.SvcBPub, err = materialToKeys(vs.Keys["svcB"]); err != nil {
		return nil, fmt.Errorf("svcB: %w", err)
	}
	if kr.SvcC, kr.SvcCPub, err = materialToKeys(vs.Keys["svcC"]); err != nil {
		return nil, fmt.Errorf("svcC: %w", err)
	}
	if kr.Other, kr.OtherPub, err = materialToKeys(vs.Keys["other"]); err != nil {
		return nil, fmt.Errorf("other: %w", err)
	}
	return kr, nil
}

func materialToKeys(km keyMaterial) (priv, pub jwk.Key, err error) {
	if km.PubJWK == "" {
		return nil, nil, fmt.Errorf("missing public JWK")
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(km.PubJWK), &raw); err != nil {
		return nil, nil, err
	}
	raw["d"] = km.PrivD
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, nil, err
	}
	priv, err = jwk.ParseKey(b)
	if err != nil {
		return nil, nil, err
	}
	pub, err = priv.PublicKey()
	return priv, pub, err
}

func jwsAllowlist() *httpsign.JWSAlgAllowlist {
	al, err := httpsign.NewJWSAlgAllowlist(jwa.EdDSAEd25519(), jwa.ES256())
	if err != nil {
		panic(err)
	}
	return al
}

// setFakeCreated sets the unexported SignConfig.fakeCreated (test harness only).
func setFakeCreated(cfg *httpsign.SignConfig, ts int64) *httpsign.SignConfig {
	f := reflect.ValueOf(cfg).Elem().FieldByName("fakeCreated")
	if !f.IsValid() {
		panic("httpsign.SignConfig missing fakeCreated")
	}
	reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().SetInt(ts)
	return cfg
}

// ecdsaSignRawRFC6979 signs digest with deterministic ECDSA (nil rand → RFC 6979 in Go stdlib).
// Current v4 regen negatives use Ed25519; keep this for ES256 regen vectors.
func ecdsaSignRawRFC6979(priv *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(nil, priv, digest)
	if err != nil {
		return nil, err
	}
	curveBits := priv.Curve.Params().BitSize
	keyBytes := (curveBits + 7) / 8
	out := make([]byte, 2*keyBytes)
	r.FillBytes(out[:keyBytes])
	s.FillBytes(out[keyBytes:])
	return out, nil
}

var _ = ecdsaSignRawRFC6979
