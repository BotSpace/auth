package utils

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

func ParseRSAPUblicKeyFromPEM(publicKey []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	pubRaw, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := pubRaw.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not RSA public key")
	}
	return pub, nil
}

func CreateJWT(claims jwt.MapClaims, privKeyPEM []byte) (string, error) {
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privKeyPEM)
	if err != nil {
		return "", err
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func VerifyJWT(tokenString string, pubKeyPEM []byte) (jwt.MapClaims, error) {
	pubKey, err := ParseRSAPUblicKeyFromPEM(pubKeyPEM)
	if err != nil {
		return nil, err
	}
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return pubKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid token")
}
