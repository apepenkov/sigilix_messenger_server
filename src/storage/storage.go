package storage

import (
	"errors"
	"github.com/apepenkov/sigilix_messenger_server/proto/messages"
	"github.com/apepenkov/sigilix_messenger_server/proto/users"
)

type User struct {
	UserId              uint64
	EcdsaPublicKeyBytes []byte
	InitialRsaKeyBytes  []byte

	Username                string
	SearchByUsernameAllowed bool
}

func (u *User) ToPublicInfo() *users.PublicUserInfo {
	return &users.PublicUserInfo{
		UserId:              u.UserId,
		EcdsaPublicKey:      u.EcdsaPublicKeyBytes,
		Username:            u.Username,
		InitialRsaPublicKey: u.InitialRsaKeyBytes,
	}
}

func (u *User) ToPrivateInfo() *users.PrivateUserInfo {
	return &users.PrivateUserInfo{
		PublicInfo:              u.ToPublicInfo(),
		SearchByUsernameAllowed: u.SearchByUsernameAllowed,
	}
}

type Storage interface {
	FetchOrCreateUser(ecdsaPublicKeyBytes []byte, initialRsaKeyBytes []byte) (*User, error)
	GetUserById(userId uint64) (*User, error)
	SearchForUserByUsername(username string) (*User, error)
	SetUsernameConfig(userId uint64, username string, searchByUsernameAllowed bool) error

	PutNotifications(userId uint64, notifications ...*messages.IncomingNotification) error
	FetchAndRemoveNotifications(userId uint64, limit int) ([]*messages.IncomingNotification, error)
}

var (
	ErrUserNotFound = errors.New("user not found")
	ErrRsaMissmatch = errors.New("rsa key missmatch with stored one")
)
