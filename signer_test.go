package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"testing"

	"golang.org/x/crypto/sha3"
)

func Sign(hash []byte, privateKey *ecdsa.PrivateKey) (r, s *big.Int) {
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash)
	if err != nil {
		panic(err)
	}

	return
}

func TestSignRecoverAddress(t *testing.T) {
	curve := InitSECP256K1Curve()

	// 1. Генеруємо ключ
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Повідомлення
	msg := []byte("hello ethereum")

	hash := sha3.NewLegacyKeccak256()
	hash.Write(msg)
	digest := hash.Sum(nil)

	// 3. Підпис
	r, s := Sign(digest, privateKey)

	// 4. Recovery pubkey
	var recX, recY *big.Int
	var vFound bool

	for v := 0; v <= 1; v++ {
		x, y := recoverPublicKey(r, s, digest, v, curve)
		if x == nil {
			continue
		}
		if x.Cmp(privateKey.PublicKey.X) == 0 && y.Cmp(privateKey.PublicKey.Y) == 0 {
			recX, recY = x, y
			vFound = true
			break
		}
	}

	if !vFound {
		t.Fatal("failed to recover public key")
	}

	// 5. Address із recovered pubkey
	addrRecovered := GetAddressFromPublicKey(recX, recY)

	// 6. Address із original pubkey
	addrOriginal := GetAddressFromPublicKey(
		privateKey.PublicKey.X,
		privateKey.PublicKey.Y,
	)

	if addrRecovered != addrOriginal {
		t.Fatalf("address mismatch:\n recovered=%s\n original=%s",
			addrRecovered.Hex(),
			addrOriginal.Hex(),
		)
	}

	t.Log("SUCCESS")
	t.Log("Address:", addrRecovered.Hex())
}
