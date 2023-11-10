package memory_storage

import (
	"bytes"
	"container/list"
	"github.com/apepenkov/sigilix_messenger_server/crypto_utils"
	"github.com/apepenkov/sigilix_messenger_server/proto/messages"
	"github.com/apepenkov/sigilix_messenger_server/storage"
	"sync"
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

type inMemoryStorage struct {
	users         map[uint64]*storage.User
	usersRWLock   *sync.RWMutex
	notifications map[uint64]*NotificationBucket
	notifRWLock   *sync.RWMutex
}

func NewInMemoryStorage() storage.Storage {
	return &inMemoryStorage{
		users:         make(map[uint64]*storage.User, 0),
		usersRWLock:   &sync.RWMutex{},
		notifications: make(map[uint64]*NotificationBucket, 0),
		notifRWLock:   &sync.RWMutex{},
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

	if !(bytes.Compare(user.InitialRsaKeyBytes, initialRsaKeyBytes) == 0) {
		return nil, storage.ErrRsaMissmatch
	}

	if ok {
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
