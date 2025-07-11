// Copyright 2025 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"time"

	"code.gitea.io/gitea/models/auth"
	"code.gitea.io/gitea/modules/json"
	"github.com/crewjam/saml"
)

// Source holds configuration for the SAML login source.
type Source struct {
	auth.ConfigBase             `json:"-"`
	IdentityProviderMetadata    string
	IdentityProviderMetadataURL string
	NameIDFormat                NameIDFormat
	ServiceProviderCertificate  string
	ServiceProviderIssuer       string
	ServiceProviderPrivateKey   string
	CallbackURL                 string
	IconURL                     string
	EmailAssertionKey           string
	NameAssertionKey            string
	UsernameAssertionKey        string
	authSource                  *auth.Source
	samlSP                      *saml.ServiceProvider
}

func GenerateSAMLSPKeypair() (string, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", "", err
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	keyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: keyBytes,
		},
	)

	now := time.Now()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(365 * 24 * time.Hour),

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,
	}

	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}

	certPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificate,
		},
	)

	return string(keyPem), string(certPem), nil
}

// FromDB fills up an SAMLConfig from serialized format.
func (source *Source) FromDB(bs []byte) error {
	return json.UnmarshalHandleDoubleEncode(bs, &source)
}

// ToDB exports an SAMLConfig to a serialized format.
func (source *Source) ToDB() ([]byte, error) {
	return json.Marshal(source)
}

func init() {
	auth.RegisterTypeConfig(auth.SAML, &Source{})
}
