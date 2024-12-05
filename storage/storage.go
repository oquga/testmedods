package storage

import "time"

var AuthSet = make(map[string]AuthorizedUser)

type UserInfo struct {
	Uuid  string
	Email string
	Ip    string
}

type AuthorizedUser struct {
	uuid       string
	email      string
	ip         string
	aExpiresAt int64
	rToken     string
	rExpiresAt int64
	revoked    bool
}

func SaveAuthorizedUser(uuid string, email string, ip string, timeNow time.Time, refreshToken string) {
	authorizedUser := AuthorizedUser{
		uuid:       uuid,
		email:      email,
		ip:         ip,
		aExpiresAt: timeNow.Add(15 + time.Minute).Unix(),
		rToken:     refreshToken,
		rExpiresAt: timeNow.Add(time.Hour).Unix(),
		revoked:    false,
	}

	AuthSet[uuid] = authorizedUser
}
