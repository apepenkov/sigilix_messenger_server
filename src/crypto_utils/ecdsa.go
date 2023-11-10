package crypto_utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/big"
)

var EllipticCurve = elliptic.P521()

func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(EllipticCurve, crand.Reader)
}

func Base64ToBytes(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

func PublicECDSAKeyFromBytes(data []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(EllipticCurve, data)
	if x == nil {
		return nil, errors.New("invalid ECDSA public key")
	}
	return &ecdsa.PublicKey{Curve: EllipticCurve, X: x, Y: y}, nil
}

func PublicECDSAKeyToBytes(key *ecdsa.PublicKey) []byte {
	return elliptic.Marshal(key.Curve, key.X, key.Y)
}

func ValidateECDSASignature(pubKey *ecdsa.PublicKey, data []byte, signature []byte) bool {
	hashed := sha512.Sum512(data)

	r := new(big.Int).SetBytes(signature[:len(signature)/2])
	s := new(big.Int).SetBytes(signature[len(signature)/2:])

	return ecdsa.Verify(pubKey, hashed[:], r, s)
}

func ValidateECDSASignatureFromBase64(pubKeyBytes []byte, data []byte, signatureBase64 string) (bool, error) {
	pubKey, err := PublicECDSAKeyFromBytes(pubKeyBytes)
	if err != nil {
		return false, err
	}

	signature, err := Base64ToBytes(signatureBase64)
	if err != nil {
		return false, err
	}
	return ValidateECDSASignature(pubKey, data, signature), nil
}

func GenerateUserIdByPublicKey(publicKey *ecdsa.PublicKey) uint64 {
	hashBytes := sha256.Sum256(elliptic.Marshal(publicKey.Curve, publicKey.X, publicKey.Y))
	return binary.BigEndian.Uint64(hashBytes[:8])
}
