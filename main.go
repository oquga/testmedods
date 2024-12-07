package main

import (
	"fmt"
	"net"
	"net/http"
	"net/mail"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"testask.com/storage"
	"testask.com/utils"
)

func isValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func isValidUUID(u string) bool {
	_, err := uuid.Parse(u)
	return err == nil
}

func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func main() {
	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		// requestUUID := r.FormValue("uuid")
		requestEmail := r.FormValue("email")
		requestUUID := r.Header.Get("X-Requested-With")
		requestIp, err := utils.GetIP(r)
		if err != nil {
			w.WriteHeader(400)
			w.Write([]byte("No valid ip"))
			return
		}

		// TODO: validate credentials, email: @mail.com; uuid: correct uuid;
		if isValidIP(requestIp) && isValidEmail(requestEmail) && isValidUUID(requestUUID) {
			authUser := storage.UserDTO{Uuid: requestUUID, Email: requestEmail, Ip: requestIp}
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
		accessToken, err := r.Cookie("AccessToken")
		if err != nil {
			fmt.Fprintf(w, "Access token is required in cookies")
			return
		}

		aTokenString := strings.Join(strings.Split(accessToken.String(), "AccessToken="), "")

		claims, err := utils.ParseTokenClaims(aTokenString)
		if err != nil {
			fmt.Fprintf(w, "Failed to parse access token")
			return
		}

		currentUserUUID, err := claims.GetSubject()
		if err != nil {
			fmt.Fprintf(w, "UUID is not credential")
			return
		}

		currentUser := storage.GetUserByUUID(currentUserUUID)

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
					fmt.Fprintf(w, "Email is not credential")
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

		refreshToken, err := r.Cookie("RefreshToken")
		if err != nil {
			fmt.Fprintf(w, "Refresh token is required in cookies")
			return
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
		accessToken, err := r.Cookie("AccessToken")
		if err != nil {
			fmt.Fprintf(w, "Access token is required in cookies")
			return
		}

		aTokenString := strings.Join(strings.Split(accessToken.String(), "AccessToken="), "")

		claims := jwt.MapClaims{}
		// Parse the claims
		_, err = jwt.ParseWithClaims(aTokenString, claims, func(token *jwt.Token) (interface{}, error) {
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

		currentUserUUID, err := claims.GetSubject()
		if err != nil {
			fmt.Fprintf(w, "UUID is not credential")
			return
		}

		currentUser := storage.GetUserByUUID(currentUserUUID)

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

		fmt.Fprintf(w, storage.PrintAuthorizedUser(currentUser))
		return
	})

	http.ListenAndServe(":80", nil)
}
