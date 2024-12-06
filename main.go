package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"testask.com/storage"
	"testask.com/utils"
)

var RevokedMap map[string]bool //rToken: true, false

func main() {
	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		uuidClient := r.FormValue("uuid")
		email := r.FormValue("email")

		clientIp, err := utils.GetIP(r)
		if err != nil {
			w.WriteHeader(400)
			w.Write([]byte("No valid ip"))
			return
		}

		fmt.Printf("%s\n%s\n%s\n", email, clientIp, uuidClient)

		authUser := storage.UserDTO{Uuid: uuidClient, Email: email, Ip: clientIp}

		if email == "email" { // TODO: validate credentials, email: @mail.com; uuid: correct uuid;

			aToken, rToken, err := utils.CreateTokenPair(authUser)

			if err != nil {
				http.Error(w, "Failed", http.StatusInternalServerError)
				return
			}

			w.Write([]byte("AT:\n"))
			w.Write([]byte(aToken))
			w.Write([]byte("\n------\n"))
			w.Write([]byte("RT:\n"))
			w.Write([]byte(rToken))
			return
		}
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
	})

	http.HandleFunc("/refresh", func(w http.ResponseWriter, r *http.Request) {
		// Access, Refresh токены обоюдно связаны,
		// Refresh операцию для Access токена можно выполнить только тем Refresh токеном который был выдан вместе с ним.

		// В случае, если ip адрес изменился, при рефреш операции нужно послать email warning на почту юзера (для упрощения можно использовать моковые данные).
		fmt.Fprintf(w, "REFRESH")
	})

	http.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		clientToken := r.Header.Get("Authorization")

		if clientToken == "" {
			fmt.Fprintf(w, "Authorization Token is required")
			return
		}

		tokenString := strings.Join(strings.Split(clientToken, "Bearer "), "")
		claims := jwt.MapClaims{}
		// Parse the claims
		_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return utils.SecretKey, nil
		})

		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				fmt.Printf("%s\n", err)
				return
			}
			fmt.Printf("%s\n", err)
			return
		}

		currentUser, err := storage.GetUserByUUID(claims.GetSubject())

		if err != nil {
			fmt.Printf("UserNotFound: %s\n", err)
			return
		}

		userDTO := storage.UserDTO{Uuid: currentUser.FieldByName("uuid").String()}
		for key, val := range claims {
			if key == "email" {
				userDTO.Email = val.(string)
			}
			if key == "ip" {
				userDTO.Ip = val.(string)
			}
		}

		if userDTO.Email != storage.GetEmail(currentUser) || userDTO.Uuid != storage.GetUUID(currentUser) {
			fmt.Printf("Credentials are NOT satisfied\n")
			return
		}

		if userDTO.Ip != storage.GetIP(currentUser) {
			fmt.Printf("Malicious activity found\n")
		}

		storage.PrintAuthorizedUser(currentUser)
		fmt.Printf("Credentials are satisfied\n")
	})

	http.ListenAndServe(":80", nil)
}
