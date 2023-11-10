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

const EllipticCurveBitSize = 521

func SerializeSignature(r, s *big.Int) []byte {
	keySizeInBytes := (EllipticCurveBitSize + 7) / 8
	ret := make([]byte, 2*keySizeInBytes)
	r.FillBytes(ret[:keySizeInBytes])
	s.FillBytes(ret[keySizeInBytes:])
	return ret
}

func DeserializeSignature(signature []byte) (*big.Int, *big.Int, error) {
	keySizeInBytes := (EllipticCurveBitSize + 7) / 8
	if len(signature) != 2*keySizeInBytes {
		return nil, nil, errors.New("signature is not the correct size")
	}
	r := new(big.Int).SetBytes(signature[:keySizeInBytes])
	s := new(big.Int).SetBytes(signature[keySizeInBytes:])
	return r, s, nil
}

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

func HashData(data []byte) []byte {
	hashed := sha512.Sum512(data)
	return hashed[:]
}

func ValidateECDSASignature(pubKey *ecdsa.PublicKey, data []byte, signature []byte) (bool, error) {
	hashed := HashData(data)

	r, s, err := DeserializeSignature(signature)
	if err != nil {
		return false, err
	}

	return ecdsa.Verify(pubKey, hashed, r, s), nil
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
	return ValidateECDSASignature(pubKey, data, signature)
}

func GenerateUserIdByPublicKey(publicKey *ecdsa.PublicKey) uint64 {
	hashBytes := sha256.Sum256(elliptic.Marshal(publicKey.Curve, publicKey.X, publicKey.Y))
	return binary.BigEndian.Uint64(hashBytes[:8])
}

func SignMessage(privateKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	hashed := HashData(data)

	r, s, err := ecdsa.Sign(crand.Reader, privateKey, hashed)
	if err != nil {
		return nil, err
	}

	signature := SerializeSignature(r, s)
	return signature, nil
}

func SignMessageBase64(privateKey *ecdsa.PrivateKey, data []byte) (string, error) {
	signature, err := SignMessage(privateKey, data)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}
