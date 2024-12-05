package storage

import (
	"reflect"
	"time"
)

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

func GetUserByUUID(uuid string, err error) (reflect.Value, error) {
	if err != nil {
		return reflect.ValueOf("Error"), err
	}

	user := reflect.ValueOf(AuthSet[uuid])
	return user, nil
}

func GetUUID(user reflect.Value) string {
	return user.FieldByName("uuid").String()
}

func GetEmail(user reflect.Value) string {
	return user.FieldByName("email").String()
}

func GetIP(user reflect.Value) string {
	return user.FieldByName("ip").String()
}

func GetRefreshToken(user reflect.Value) string {
	return user.FieldByName("rToken").String()
}

func GetRevokedStatus(user reflect.Value) bool {
	return user.FieldByName("revoked").Bool()
}
