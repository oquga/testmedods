package utils

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var SecretKey = []byte("secret")

type UserInfo struct {
	Uuid  string
	Email string
	Ip    string
}

// type Claims struct {
// 	*jwt.StandardClaims
// 	UserInfo
// }

// func generateUUID() string {
// 	uuidWithHyphen := uuid.New()
// 	return uuidWithHyphen.String()
// }

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

func CreateTokenPair(user UserInfo) (string, string, error) {
	// Access токен тип JWT, алгоритм SHA512, хранить в базе строго запрещено.

	authClaims := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub":  user.Uuid,
		"mail": user.Email,
		"ip":   user.Ip,
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(15 + time.Minute).Unix(),
	})

	authToken, err := authClaims.SignedString(SecretKey)
	if err != nil {
		fmt.Printf("%s", err)
		return "", "", err
	}

	fmt.Printf("Auth Token: %+v\n", authClaims)

	// Refresh токен тип произвольный, формат передачи base64,
	// хранится в базе исключительно в виде bcrypt хеша,
	// должен быть защищен от изменения на стороне клиента и попыток повторного использования.

	rtClaims := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": user.Uuid,
		"ip":  user.Ip,
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	refreshToken, err := rtClaims.SignedString(SecretKey)
	if err != nil {
		return "", "", err
	}

	// Payload токенов должен содержать сведения об ip адресе клиента, которому он был выдан
	return authToken, refreshToken, err
}
