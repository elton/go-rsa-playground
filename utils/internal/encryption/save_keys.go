// Copyright 2020 Elton Zheng
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package encryption

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
)

// ExportPubKeyAsPEMStr Export public key as string in PEM format.
func ExportPubKeyAsPEMStr(pubkey *rsa.PublicKey) string {
	pubKeyPEM := string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(pubkey),
		},
	))
	return pubKeyPEM
}

// ExportPrivateKeyAsPEMStr Export private key as string in PEM format.
func ExportPrivateKeyAsPEMStr(privkey *rsa.PrivateKey) string {
	privKeyPEM := string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privkey),
		},
	))
	return privKeyPEM
}

// SaveKeyToFile Save string to a file.
func SaveKeyToFile(keyPEM, filename string) {
	pemBytes := []byte(keyPEM)
	ioutil.WriteFile(filename, pemBytes, 0400)
}
