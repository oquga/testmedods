package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"testask.com/storage"
)

var SecretKey = []byte("secret")

func CheckTokenHash(token, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(token))
	return err == nil
}

func hashToken(token string) (string, error) {
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

func CreateTokenPair(user storage.UserDTO) (string, string, error) {
	// Access токен тип JWT, алгоритм SHA512, хранить в базе строго запрещено.
	currentTime := time.Now()

	authClaims := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub":   user.Uuid,
		"email": user.Email,
	})

	authToken, err := authClaims.SignedString(SecretKey)
	if err != nil {
		fmt.Printf("%s", err)
		return "", "", err
	}

	// fmt.Printf("Auth Token: %+v\n", authClaims)

	// Refresh токен тип произвольный, формат передачи base64,
	// хранится в базе исключительно в виде bcrypt хеша,
	// должен быть защищен от изменения на стороне клиента и попыток повторного использования.

	rtClaims := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": user.Uuid,
	})

	refreshToken, err := rtClaims.SignedString(SecretKey)
	if err != nil {
		return "", "", err
	}

	//add to storage info about user: uuid, email, ip, issuedAt
	hashedRefreshToken, err := hashToken(refreshToken)
	if err != nil {
		fmt.Println(err)
		// return "", "", err
	}

	fmt.Println("RT: " + refreshToken)
	fmt.Println("Hashed RT: " + hashedRefreshToken)

	// storage.SaveAuthorizedUser(user.Uuid, user.Email, user.Ip, currentTime, refreshToken)
	storage.SaveAuthorizedUser(user.Uuid, user.Email, user.Ip, currentTime, hashedRefreshToken)

	// Payload токенов должен содержать сведения об ip адресе клиента, которому он был выдан
	return authToken, refreshToken, err
}
