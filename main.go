package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type UserInfo struct {
	Uuid  string
	Email string
	Ip    string
}

// type Claims struct {
// 	*jwt.StandardClaims
// 	UserInfo
// }

var secretKey = []byte("secret")

func generateUUID() string {
	uuidWithHyphen := uuid.New()
	return uuidWithHyphen.String()
}

func getIP(r *http.Request) (string, error) {
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
	return "", fmt.Errorf("No valid ip found")
}

func createTokenPair(user UserInfo) (string, string, error) {
	authClaims := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub":  user.Uuid,
		"mail": user.Email,
		"ip":   user.Ip,
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(15 + time.Minute).Unix(),
	})

	authToken, err := authClaims.SignedString(secretKey)
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
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	refreshToken, err := rtClaims.SignedString(secretKey)
	if err != nil {
		return "", "", err
	}

	return authToken, refreshToken, err
}

func main() {
	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		email := r.FormValue("email")
		//password := r.FormValue("password")

		uuidClient := generateUUID()

		clientIp, err := getIP(r)
		if err != nil {
			w.WriteHeader(400)
			w.Write([]byte("No valid ip"))
			return
		}

		fmt.Printf("%s\n%s\n%s\n", email, clientIp, uuidClient)

		authUser := UserInfo{Uuid: uuidClient, Email: email, Ip: clientIp}

		if email == "email" {
			aToken, rToken, err := createTokenPair(authUser)
			if err != nil {
				http.Error(w, "Failed", http.StatusInternalServerError)
				return
			}

			w.Write([]byte(aToken))
			w.Write([]byte("\n-----------------\n"))
			w.Write([]byte(rToken))
			return
		}
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		// fmt.Fprintf(w, "AUTH")
	})

	http.HandleFunc("/refresh", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "REFRESH")
	})

	http.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		clientToken := r.Header.Get("Authorization")

		if clientToken == "" {
			fmt.Fprintf(w, "Authorization Token is required")
			return
		}

		claims := jwt.MapClaims{}
		tokenString := strings.Join(strings.Split(clientToken, "Bearer "), "")

		// Parse the claims
		_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return secretKey, nil
		})

		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				fmt.Printf("%s\n", err)
				return
			}
			fmt.Printf("%s\n", err)
			return
		}

		for key, val := range claims {
			fmt.Printf("Key: %v, value: %v\n", key, val)
		}

	})

	http.ListenAndServe(":80", nil)
}
