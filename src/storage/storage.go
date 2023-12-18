package storage

import (
	"github.com/apepenkov/sigilix_messenger_server/custom_types"
	"github.com/apepenkov/sigilix_messenger_server/errors_impl"
	"time"
)

type User struct {
	UserId              uint64
	EcdsaPublicKeyBytes []byte
	InitialRsaKeyBytes  []byte

	Username                string
	SearchByUsernameAllowed bool
}

func (u *User) ToPublicInfo() *custom_types.PublicUserInfo {
	return &custom_types.PublicUserInfo{
		UserId:              u.UserId,
		EcdsaPublicKey:      u.EcdsaPublicKeyBytes,
		Username:            u.Username,
		InitialRsaPublicKey: u.InitialRsaKeyBytes,
	}
}

func (u *User) ToPrivateInfo() *custom_types.PrivateUserInfo {
	return &custom_types.PrivateUserInfo{
		PublicInfo:              u.ToPublicInfo(),
		SearchByUsernameAllowed: u.SearchByUsernameAllowed,
	}
}

type ChatState int

const (
	ChatStateInitiatorRequested ChatState = iota
	ChatStateReceiverAccepted
	ChatStateReady
)

type Chat struct {
	CreatedAt   time.Time
	ChatId      uint64
	InitiatorId uint64
	ReceiverId  uint64
	State       ChatState
}

type Storage interface {
	FetchOrCreateUser(ecdsaPublicKeyBytes []byte, initialRsaKeyBytes []byte) (*User, error)
	GetUserById(userId uint64) (*User, error)
	SearchForUserByUsername(username string) (*User, error)
	SetUsernameConfig(userId uint64, username string, searchByUsernameAllowed bool) error

	PutNotifications(userId uint64, notifications ...*custom_types.IncomingNotification) error
	FetchAndRemoveNotifications(userId uint64, limit int) ([]*custom_types.IncomingNotification, error)

	CreateChat(initiatorId uint64, receiverId uint64) (*Chat, *User, *User, error)
	GetChat(chatId uint64) (*Chat, error)
	GetChatByUsers(userA uint64, userB uint64) (*Chat, error)
	UpdateChatState(chatId uint64, state ChatState) error
	DestroyChat(chatId uint64) error // should be destroyed after 24 hours, if not accepted by receiver
	GetNextMessageId(chatId uint64) (uint64, error)
}

var (
	//ErrUserNotFound = errors.New("user not found")
	//ErrRsaMissmatch = errors.New("rsa key missmatch with stored one")
	//ErrChatNotFound = errors.New("chat not found")
	ErrUserNotFound = errors_impl.Error{Code: errors_impl.ErrNotFound, Message: "user not found"}
	ErrRsaMissmatch = errors_impl.Error{Code: errors_impl.ErrPermissionDenied, Message: "rsa key missmatch with stored one"}
	ErrChatNotFound = errors_impl.Error{Code: errors_impl.ErrNotFound, Message: "chat not found"}
)
