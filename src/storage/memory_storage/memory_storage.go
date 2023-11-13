package memory_storage

import (
	"bytes"
	"container/list"
	"github.com/apepenkov/sigilix_messenger_server/crypto_utils"
	"github.com/apepenkov/sigilix_messenger_server/proto/messages"
	"github.com/apepenkov/sigilix_messenger_server/storage"
	"sync"
	"time"
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type NotificationBucket struct {
	NotifList *list.List
}

func (nb *NotificationBucket) Add(notifications ...*messages.IncomingNotification) {
	for _, notif := range notifications {
		nb.NotifList.PushBack(notif)
	}
}

func (nb *NotificationBucket) Pop(n int) []*messages.IncomingNotification {
	actualN := min(n, nb.NotifList.Len())
	if actualN == 0 {
		return []*messages.IncomingNotification{}
	}
	ret := make([]*messages.IncomingNotification, actualN)
	for i := 0; i < actualN; i++ {
		ret[i] = nb.NotifList.Front().Value.(*messages.IncomingNotification)
		nb.NotifList.Remove(nb.NotifList.Front())
	}
	return ret
}

type ChatBucket struct {
	Chat          *storage.Chat
	LastMessageId uint64
}

type inMemoryStorage struct {
	users       map[uint64]*storage.User
	usersRWLock *sync.RWMutex

	notifications map[uint64]*NotificationBucket
	notifRWLock   *sync.RWMutex

	chats       map[uint64]*ChatBucket
	chatsRWLock *sync.RWMutex
	lastChatId  uint64
}

func NewInMemoryStorage() storage.Storage {
	return &inMemoryStorage{
		users:         make(map[uint64]*storage.User),
		usersRWLock:   &sync.RWMutex{},
		notifications: make(map[uint64]*NotificationBucket),
		notifRWLock:   &sync.RWMutex{},
		chats:         make(map[uint64]*ChatBucket),
		chatsRWLock:   &sync.RWMutex{},
		lastChatId:    0,
	}
}

func (s *inMemoryStorage) getNotificationBucket(userId uint64) *NotificationBucket {
	s.notifRWLock.RLock()
	bucket, ok := s.notifications[userId]
	s.notifRWLock.RUnlock()
	if !ok {
		bucket = &NotificationBucket{
			NotifList: list.New(),
		}
		s.notifRWLock.Lock()
		s.notifications[userId] = bucket
		s.notifRWLock.Unlock()
	}
	return bucket
}

func (s *inMemoryStorage) FetchOrCreateUser(ecdsaPublicKeyBytes []byte, initialRsaKeyBytes []byte) (*storage.User, error) {
	pub, err := crypto_utils.PublicECDSAKeyFromBytes(ecdsaPublicKeyBytes)
	if err != nil {
		return nil, err
	}
	userId := crypto_utils.GenerateUserIdByPublicKey(pub)

	s.usersRWLock.RLock()
	user, ok := s.users[userId]
	s.usersRWLock.RUnlock()

	if ok {
		if !(bytes.Compare(user.InitialRsaKeyBytes, initialRsaKeyBytes) == 0) {
			return nil, storage.ErrRsaMissmatch
		}
		return user, nil
	} else {
		user = &storage.User{
			UserId:                  userId,
			EcdsaPublicKeyBytes:     ecdsaPublicKeyBytes,
			InitialRsaKeyBytes:      initialRsaKeyBytes,
			Username:                "",
			SearchByUsernameAllowed: false,
		}

		s.usersRWLock.Lock()
		s.users[userId] = user
		s.usersRWLock.Unlock()

		return user, nil
	}
}

func (s *inMemoryStorage) GetUserById(userId uint64) (*storage.User, error) {
	s.usersRWLock.RLock()
	user, ok := s.users[userId]
	s.usersRWLock.RUnlock()

	if !ok {
		return nil, storage.ErrUserNotFound
	}

	return user, nil
}

func (s *inMemoryStorage) SearchForUserByUsername(username string) (*storage.User, error) {
	for _, user := range s.users {
		if user.Username == username {
			if !user.SearchByUsernameAllowed {
				return nil, nil // we don't want to leak information about users who don't want to be found
			}
		}
	}
	return nil, nil
}

func (s *inMemoryStorage) SetUsernameConfig(userId uint64, username string, searchByUsernameAllowed bool) error {
	s.usersRWLock.Lock()
	user, ok := s.users[userId]
	s.usersRWLock.Unlock()

	if !ok {
		return storage.ErrUserNotFound
	}

	user.Username = username
	user.SearchByUsernameAllowed = searchByUsernameAllowed
	return nil
}

func (s *inMemoryStorage) PutNotifications(userId uint64, notifications ...*messages.IncomingNotification) error {
	s.getNotificationBucket(userId).Add(notifications...)
	return nil
}

func (s *inMemoryStorage) FetchAndRemoveNotifications(userId uint64, limit int) ([]*messages.IncomingNotification, error) {
	return s.getNotificationBucket(userId).Pop(limit), nil
}

func (s *inMemoryStorage) CreateChat(initiatorId uint64, receiverId uint64) (*storage.Chat, *storage.User, *storage.User, error) {
	initiator, err := s.GetUserById(initiatorId)
	if err != nil {
		return nil, nil, nil, err
	}
	receiver, err := s.GetUserById(receiverId)
	if err != nil {
		return nil, nil, nil, err
	}
	s.chatsRWLock.Lock()
	newChat := &storage.Chat{
		CreatedAt:   time.Now(),
		ChatId:      s.lastChatId,
		InitiatorId: initiatorId,
		ReceiverId:  receiverId,
		State:       storage.ChatStateInitiatorRequested,
	}
	s.chats[s.lastChatId] = &ChatBucket{
		Chat:          newChat,
		LastMessageId: 0,
	}
	s.lastChatId++
	s.chatsRWLock.Unlock()

	return newChat, initiator, receiver, nil
}

func (s *inMemoryStorage) GetChat(chatId uint64) (*storage.Chat, error) {
	s.chatsRWLock.RLock()
	chatBucket, ok := s.chats[chatId]
	s.chatsRWLock.RUnlock()
	if !ok {
		return nil, storage.ErrChatNotFound
	}
	return chatBucket.Chat, nil
}

func (s *inMemoryStorage) GetChatByUsers(userA uint64, userB uint64) (*storage.Chat, error) {
	for _, chatBucket := range s.chats {
		chat := chatBucket.Chat
		if (chat.InitiatorId == userA && chat.ReceiverId == userB) ||
			(chat.InitiatorId == userB && chat.ReceiverId == userA) {
			return chat, nil
		}
	}
	return nil, storage.ErrChatNotFound
}

func (s *inMemoryStorage) UpdateChatState(chatId uint64, state storage.ChatState) error {
	s.chatsRWLock.Lock()
	chatBucket, ok := s.chats[chatId]
	s.chatsRWLock.Unlock()
	if !ok {
		return storage.ErrChatNotFound
	}
	chatBucket.Chat.State = state
	return nil
}

func (s *inMemoryStorage) DestroyChat(chatId uint64) error {
	s.chatsRWLock.Lock()
	delete(s.chats, chatId)
	s.chatsRWLock.Unlock()
	return nil
}

func (s *inMemoryStorage) GetNextMessageId(chatId uint64) (uint64, error) {
	s.chatsRWLock.Lock()
	chatBucket, ok := s.chats[chatId]
	s.chatsRWLock.Unlock()
	if !ok {
		return 0, storage.ErrChatNotFound
	}
	chatBucket.LastMessageId++
	return chatBucket.LastMessageId, nil
}
