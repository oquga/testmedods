package storage

import (
	"reflect"
	"time"
)

var AuthSet = make(map[string]AuthorizedUser)

type UserDTO struct {
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
	revoked    string
}

func PrintAuthorizedUser(user reflect.Value) string {
	return ("---------------") +
		("\nUUID: " + GetUUID(user) +
			", \nIP: " + GetIP(user) +
			", \nEmail: " + GetEmail(user) +
			", \nHashed RT: " + GetRefreshToken(user) +
			", \nRevoked Status: " + GetRevokedStatus(user))
}

func SaveAuthorizedUser(uuid string, email string, ip string, timeNow time.Time, refreshToken string, revokedToken string) {
	authorizedUser := AuthorizedUser{
		uuid:       uuid,
		email:      email,
		ip:         ip,
		aExpiresAt: timeNow.Add(15 + time.Minute).Unix(),
		rToken:     refreshToken,
		rExpiresAt: timeNow.Add(time.Hour).Unix(),
		revoked:    revokedToken,
	}

	AuthSet[uuid] = authorizedUser
}

func DeleteAuthorizedUser(user reflect.Value) {
	delete(AuthSet, user.FieldByName("uuid").String())
}

func GetUserByUUID(uuid string) reflect.Value {
	return reflect.ValueOf(AuthSet[uuid])
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

func ExpirationAccessToken(user reflect.Value) int64 {
	return user.FieldByName("aExpiresAt").Int()
}

func GetRefreshToken(user reflect.Value) string {
	return user.FieldByName("rToken").String()
}

func ExpirationRefreshToken(user reflect.Value) int64 {
	return user.FieldByName("rExpiresAt").Int()
}

func GetRevokedStatus(user reflect.Value) string {
	return user.FieldByName("revoked").String()
}

func SetRevokedToken(uuid, oldToken string) {
	revokedUser := AuthSet[uuid]
	revokedUser.revoked = oldToken
	AuthSet[uuid] = revokedUser
}
