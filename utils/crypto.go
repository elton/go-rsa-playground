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

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	"github.com/elton/go-rsa-playground/utils/internal/encryption"
)

func main() {
	// Generate a 2048-bits key pair
	privateKey, publicKey := encryption.GenerateKeyPair(2048)

	fmt.Printf("Private Key: %v\n", privateKey)
	fmt.Printf("Public Key: %v\n", publicKey)

	// Create PEM string
	privKeyStr := encryption.ExportPrivateKeyAsPEMStr(privateKey)
	pubKeyStr := encryption.ExportPubKeyAsPEMStr(publicKey)

	fmt.Println(privKeyStr)
	fmt.Println(pubKeyStr)

	encryption.SaveKeyToFile(privKeyStr, "privkey.pem")
	encryption.SaveKeyToFile(pubKeyStr, "pubkey.pem")

	privKeyFile := encryption.ExportPEMFileToPrivKey("privkey.pem")
	fmt.Printf("Private Key: %v\n", privKeyFile)

	message := []byte("super secret message")
	chiperText, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		publicKey,
		message,
		nil,
	)
	if err != nil {
		panic(err)
	}

	fmt.Println("Encrypted message: ", chiperText)
}
