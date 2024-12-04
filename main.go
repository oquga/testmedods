package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
)

type UserInfo struct {
	Guid  string
	Email string
	Ip    string
}

type Claims struct {
	*jwt.StandardClaims
	UserInfo
}

const secretKey = "secret"

func createToken(email string) (string, error) {
	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": email,
		//"guid": guid
		//"ip": deviceIp
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	tokenString, err := claims.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	fmt.Printf("Token: %+v\n", claims)
	return tokenString, err
}

// func checkJwt(w http.ResponseWriter, r *http.Request) {
// 	w.Write([]byte("You have accessed a protected endpoint"))
// }

func main() {
	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		email := r.FormValue("email")
		password := r.FormValue("password")

		fmt.Printf("%s\n", email)

		if email == "email" && password == "password" {
			token, err := createToken(email)
			if err != nil {
				http.Error(w, "Failed", http.StatusInternalServerError)
				return
			}

			w.Write([]byte(token))
			return
		}
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		// fmt.Fprintf(w, "AUTH")
	})

	http.HandleFunc("/refresh", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "REFRESH")
	})

	http.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {

	})

	http.ListenAndServe(":80", nil)
}
