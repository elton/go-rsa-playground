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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	"github.com/elton/go-rsa-playground/utils/internal/encryption"
)

// follow the article from https://levelup.gitconnected.com/a-guide-to-rsa-encryption-in-go-1a18d827f35d
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

	// Save PEM string to a file.
	encryption.SaveKeyToFile(privKeyStr, "privkey.pem")
	encryption.SaveKeyToFile(pubKeyStr, "pubkey.pem")

	privKeyFile := encryption.ExportPEMFileToPrivKey("privkey.pem")
	fmt.Printf("Private Key: %v\n", privKeyFile)

	//  This function uses the method OAEP to ensure that encrypting the same message twice does not result in the same ciphertext.
	// The message we want to encrypt. It must be shorter than the public modulus (2048 bits, in our case) minus twice the hash length (32 bytes) minus 2. For our case, the message must be 190 bytes at maximum.
	message := []byte("super secret message")
	cipherText, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		publicKey,
		message,
		nil,
	)
	if err != nil {
		panic(err)
	}

	fmt.Println("Encrypted message: ", cipherText)

	// Dectrypt the message using ras.DecryptOAEP function.
	decMessage, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, cipherText, nil)
	fmt.Printf("Original: %s\n", decMessage)

	// Sign the message using rsa.SignPSS
	msgHash := sha256.New()
	msgHash.Write(message)
	msgHashSum := msgHash.Sum(nil)
	// We have to provide a random reader, so every time we sign, we have a different signature.
	signature, _ := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, msgHashSum, nil)

	// Verify the signature
	err = rsa.VerifyPSS(publicKey, crypto.SHA256, msgHashSum, signature, nil)
	if err != nil {
		fmt.Println("Verification failed: ", err)
	} else {
		fmt.Println("Message verified.")
	}
}
