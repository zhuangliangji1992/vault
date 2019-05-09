package vault

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hashicorp/go-uuid"
	"gopkg.in/square/go-jose.v2"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type audience []string

type idTokenClaims struct {
	Issuer           string   `json:"iss"`
	Subject          string   `json:"sub"`
	Audience         audience `json:"aud"`
	Expiry           int64    `json:"exp"`
	IssuedAt         int64    `json:"iat"`
	AuthorizingParty string   `json:"azp,omitempty"`
	Nonce            string   `json:"nonce,omitempty"`

	AccessTokenHash string `json:"at_hash,omitempty"`

	Email         string `json:"email,omitempty"`
	EmailVerified *bool  `json:"email_verified,omitempty"`

	Groups []string `json:"groups,omitempty"`

	Name   string      `json:"name,omitempty"`
	Claims interface{} `json:"claims",omitempty`

	//FederatedIDClaims *federatedIDClaims `json:"federated_claims,omitempty"`
}

func (ts *TokenStore) handleIDToken(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	out, err := ts.lookupInternal(ctx, req.ClientToken, false, false)

	issuedAt := time.Now()
	expiry := issuedAt.Add(2 * time.Minute)

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}

	priv := &jose.JSONWebKey{
		Key:       key,
		KeyID:     keyID,
		Algorithm: "RS256",
		Use:       "sig",
	}
	pub := &jose.JSONWebKey{
		Key:       key.Public(),
		KeyID:     keyID,
		Algorithm: "RS256",
		Use:       "sig",
	}
	_ = pub

	tok := idTokenClaims{
		Issuer:   "an_issuer",
		Subject:  "a_subject",
		Nonce:    "a_nonce",
		Expiry:   expiry.Unix(),
		IssuedAt: issuedAt.Unix(),
		Claims:   out,
	}

	payload, err := json.Marshal(tok)

	idToken, err := signPayload(priv, jose.RS256, payload)

	jwks := jose.JSONWebKeySet{
		Keys: make([]jose.JSONWebKey, 1),
	}
	jwks.Keys[0] = *pub

	//data2, err := json.MarshalIndent(jwks, "", "  ")

	return &logical.Response{
		Data: map[string]interface{}{
			"token": idToken,
			"pub":   jwks,
		},
	}, nil
}

//func (ts *TokenStore) getClaims() {
//	ts.
//		entity, err = i.MemDBEntityByID(id, false)
//	if err != nil {
//		return nil, err
//	}
//}

func signPayload(key *jose.JSONWebKey, alg jose.SignatureAlgorithm, payload []byte) (jws string, err error) {
	signingKey := jose.SigningKey{Key: key, Algorithm: alg}

	signer, err := jose.NewSigner(signingKey, &jose.SignerOptions{})
	if err != nil {
		return "", fmt.Errorf("new signier: %v", err)
	}
	signature, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("signing payload: %v", err)
	}
	return signature.CompactSerialize()
}
