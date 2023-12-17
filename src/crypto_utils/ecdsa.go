package crypto_utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/big"
)

var EllipticCurve = elliptic.P256()

var EllipticCurveBitSize = EllipticCurve.Params().BitSize // 256

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

func BytesToBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
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
	hashed := sha256.Sum256(data)
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
	return binary.BigEndian.Uint64(hashBytes[:4])
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
	return BytesToBase64(signature), nil
}

func PrivateKeyToBytes(privateKey *ecdsa.PrivateKey) []byte {
	keySizeInBytes := (EllipticCurveBitSize + 7) / 8
	ret := make([]byte, keySizeInBytes)
	privateKey.D.FillBytes(ret)
	return append(ret, PublicECDSAKeyToBytes(&privateKey.PublicKey)...)
}

func PrivateKeyToBytesBase64(privateKey *ecdsa.PrivateKey) string {
	return BytesToBase64(PrivateKeyToBytes(privateKey))
}

func PrivateKeyFromBytes(data []byte) (*ecdsa.PrivateKey, error) {
	keySizeInBytes := (EllipticCurveBitSize + 7) / 8
	if len(data) != (3*keySizeInBytes)+1 { // 1 byte for the curve type
		return nil, errors.New("invalid ECDSA private key")
	}
	d := new(big.Int).SetBytes(data[:keySizeInBytes])
	x, y := elliptic.Unmarshal(EllipticCurve, data[keySizeInBytes:])
	if x == nil {
		return nil, errors.New("invalid ECDSA public key")
	}
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: EllipticCurve, X: x, Y: y}, D: d}, nil
}

func PrivateKeyFromBytesBase64(data string) (*ecdsa.PrivateKey, error) {
	bytes, err := Base64ToBytes(data)
	if err != nil {
		return nil, err
	}
	return PrivateKeyFromBytes(bytes)
}
