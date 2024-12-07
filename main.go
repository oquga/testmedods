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

			aToken, rToken, err := utils.CreateTokenPair(authUser, "false")
			if err != nil {
				http.Error(w, "Failed", http.StatusInternalServerError)
				return
			}

			aCookie, rCookie := utils.SetTokensIntoCookies(aToken, rToken)
			http.SetCookie(w, aCookie)
			http.SetCookie(w, rCookie)
			w.WriteHeader(200)
			return
		}
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
	})

	http.HandleFunc("/refresh", func(w http.ResponseWriter, r *http.Request) {
		// Access, Refresh токены обоюдно связаны,
		// Refresh операцию для Access токена можно выполнить только тем Refresh токеном который был выдан вместе с ним.

		// clientToken := r.Header.Get("Authorization")
		// if clientToken == "" {
		// 	fmt.Fprintf(w, "Authorization Token is required")
		// 	return
		// }

		accessToken, err := r.Cookie("AccessToken")
		if err != nil {
			fmt.Fprintf(w, "Access token is required in cookies")
			return
		}

		refreshToken, err := r.Cookie("RefreshToken")
		if err != nil {
			fmt.Fprintf(w, "Refresh token is required in cookies")
			return
		}

		aTokenString := strings.Join(strings.Split(accessToken.String(), "AccessToken="), "")

		claims, err := utils.ParseTokenClaims(aTokenString)
		if err != nil {
			fmt.Fprintf(w, "Failed to parse access token")
			return
		}

		currentUser, err := storage.GetUserByUUID(claims.GetSubject())
		if err != nil {
			fmt.Fprintf(w, "UserNotFound")
			return
		}

		if utils.IsAccessTokenExpired(currentUser) {
			fmt.Fprintf(w, "Access token expired")
			return
		}

		if utils.IsRefreshTokenExpired(currentUser) {
			fmt.Fprintf(w, "Refresh token expired")
			return
		}

		// В случае, если ip адрес изменился, при рефреш операции нужно послать email warning на почту юзера (для упрощения можно использовать моковые данные).
		requestIp, err := utils.GetIP(r)
		if err != nil {
			w.WriteHeader(400)
			w.Write([]byte("No valid ip"))
			return
		}

		for key, val := range claims {
			if key == "email" {
				if val != storage.GetEmail(currentUser) {
					fmt.Fprintf(w, "NON valid credentials")
					return
				}
			}
			if key == "ip" {
				savedIPaddres := storage.GetIP(currentUser)
				if requestIp != savedIPaddres || val != savedIPaddres {
					// sendEmail(storage.GetEmail(currentUser))
					fmt.Fprintf(w, "Suspicious activity")
					// send email
				}
			}
		}

		rTokenString := strings.Join(strings.Split(refreshToken.String(), "RefreshToken="), "")

		if storage.GetRevokedStatus(currentUser) == rTokenString {
			fmt.Fprintf(w, "Old Token is used to refresh one more time")
			fmt.Fprintf(w, "All authorized sessions of that user will be ended")
			storage.DeleteAuthorizedUser(currentUser)
			return
		}

		if !utils.CheckTokenHash(rTokenString, storage.GetRefreshToken(currentUser)) {
			fmt.Fprintf(w, "Refresh Token not credential")
			return
		} else {
			refreshedUser := storage.UserDTO{
				Uuid:  storage.GetUUID(currentUser),
				Email: storage.GetEmail(currentUser),
				Ip:    storage.GetIP(currentUser),
			}

			aToken, rToken, err := utils.CreateTokenPair(refreshedUser, rTokenString)
			if err != nil {
				http.Error(w, "Failed", http.StatusInternalServerError)
				return
			}

			aCookie, rCookie := utils.SetTokensIntoCookies(aToken, rToken)

			http.SetCookie(w, aCookie)
			http.SetCookie(w, rCookie)
			w.Write([]byte("Tokens are refreshed"))
			w.WriteHeader(200)
			return
		}
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

		if userDTO.Email != storage.GetEmail(currentUser) {
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
