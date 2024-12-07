package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"testask.com/storage"
)

var SecretKey = []byte("secret")

func CheckTokenHash(token, hash string) bool {
	preprocessedToken := preprocessToken(token)
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(preprocessedToken))
	return err == nil
}

func preprocessToken(token string) string {
	sha256Hasher := sha256.New()
	sha256Hasher.Write([]byte(token))
	hashedToken := sha256Hasher.Sum(nil)
	return hex.EncodeToString(hashedToken)
}

func HashToken(token string) (string, error) {
	sha256Hasher := sha256.New()
	sha256Hasher.Write([]byte(token))
	hashedToken := sha256Hasher.Sum(nil)
	hexToken := hex.EncodeToString(hashedToken)

	bcryptHash, err := bcrypt.GenerateFromPassword([]byte(hexToken), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(bcryptHash), nil
}

func GetIP(r *http.Request) (string, error) {
	//Get IP from the X-REAL-IP header
	ip := r.Header.Get("X-REAL-IP")
	netIP := net.ParseIP(ip)
	if netIP != nil {
		return ip, nil
	}

	//Get IP from X-FORWARDED-FOR header
	ips := r.Header.Get("X-FORWARDED-FOR")
	splitIps := strings.Split(ips, ",")
	for _, ip := range splitIps {
		netIP := net.ParseIP(ip)
		if netIP != nil {
			return ip, nil
		}
	}

	//Get IP from RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", err
	}
	netIP = net.ParseIP(ip)
	if netIP != nil {
		return ip, nil
	}
	return "", fmt.Errorf("no valid ip found")
}

func CreateTokenPair(user storage.UserDTO, revokedToken string) (string, string, error) {
	// Access токен тип JWT, алгоритм SHA512, хранить в базе строго запрещено.
	currentTime := time.Now()

	authClaims := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub":   user.Uuid,
		"email": user.Email,
		"ip":    user.Ip,
		"iss":   currentTime.Unix(),
	})

	authToken, err := authClaims.SignedString(SecretKey)
	if err != nil {
		fmt.Printf("%s", err)
		return "", "", err
	}

	// Refresh токен тип произвольный, формат передачи base64,
	// хранится в базе исключительно в виде bcrypt хеша,
	// должен быть защищен от изменения на стороне клиента и попыток повторного использования.

	rtClaims := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"email": user.Email,
		"ip":    user.Ip,
		"iss":   currentTime.Unix(),
	})

	refreshToken, err := rtClaims.SignedString(SecretKey)
	if err != nil {
		return "", "", err
	}

	//add to storage info about user: uuid, email, ip, issuedAt
	hashedRefreshToken, err := HashToken(refreshToken)
	if err != nil {
		fmt.Println(err)
		return "", "", err
	}

	// fmt.Println("RT: " + refreshToken)
	// fmt.Println("Hashed RT: " + hashedRefreshToken)

	storage.SaveAuthorizedUser(user.Uuid, user.Email, user.Ip, currentTime, hashedRefreshToken, revokedToken)

	// Payload токенов должен содержать сведения об ip адресе клиента, которому он был выдан
	return authToken, refreshToken, err
}

func ParseTokenClaims(token string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	// Parse the claims
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return SecretKey, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			fmt.Printf("%s\n", err)
			return nil, err
		}
		fmt.Printf("%s\n", err)
		return nil, err
	}
	return claims, nil
}

func IsAccessTokenExpired(user reflect.Value) bool {
	// fmt.Printf("Now: %d and AT expires at %d", time.Now().Unix(), storage.ExpirationAccessToken(user))
	return time.Now().After(time.Unix(storage.ExpirationAccessToken(user), 0).UTC())
}

func IsRefreshTokenExpired(user reflect.Value) bool {
	// fmt.Printf("Now: %d and RT expires at %d", time.Now().Unix(), storage.ExpirationRefreshToken(user))
	return time.Now().After(time.Unix(storage.ExpirationRefreshToken(user), 0).UTC())
}

func SetTokensIntoCookies(aToken, rToken string) (*http.Cookie, *http.Cookie) {
	aCookie := &http.Cookie{
		Name:  "AccessToken",
		Value: aToken,
		// MaxAge: 300,
	}

	rCookie := &http.Cookie{
		Name:  "RefreshToken",
		Value: rToken,
		// MaxAge: 300,
	}

	return aCookie, rCookie
}
