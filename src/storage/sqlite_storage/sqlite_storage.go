package sqlite_storage

import (
	"database/sql"
	"github.com/apepenkov/sigilix_messenger_server/crypto_utils"
	"github.com/apepenkov/sigilix_messenger_server/custom_types"
	"github.com/apepenkov/sigilix_messenger_server/proto/messages"
	"github.com/apepenkov/sigilix_messenger_server/storage"
	_ "github.com/mattn/go-sqlite3"
	"google.golang.org/protobuf/proto"
	"time"
	"unsafe"
)

const sqlInit = `
CREATE TABLE IF NOT EXISTS users (
    user_id 					INTEGER PRIMARY KEY,
    username 					TEXT DEFAULT '',
    search_by_username_allowed 	BOOLEAN DEFAULT false,
    ecdsa_pub 					BLOB,
    rsa_pub						BLOB
);

CREATE TABLE IF NOT EXISTS chats (
    chat_id						INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at					TIMESTAMP  DEFAULT CURRENT_TIMESTAMP,
    initiator_id 				INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
    receiver_id 				INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
    state						INTEGER,
    last_message_id				INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS notifications (
    notification_id				INTEGER PRIMARY KEY AUTOINCREMENT,
    notification 				BLOB,
    user_id 					INTEGER REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS users_username_idx ON users(username);
CREATE INDEX IF NOT EXISTS users_ecdsa_pub_idx ON users(ecdsa_pub);

CREATE INDEX IF NOT EXISTS chats_initiator_id_idx ON chats(initiator_id);
CREATE INDEX IF NOT EXISTS chats_receiver_id_idx ON chats(receiver_id);

CREATE INDEX IF NOT EXISTS notifications_user_id_idx ON notifications(user_id);
`

func ByteInt64ToUint64(in int64) uint64 {
	return *(*uint64)(unsafe.Pointer(&in)) // :)
}

func Uint64ToByteInt64(in uint64) int64 {
	return *(*int64)(unsafe.Pointer(&in)) // :)
}

type sqliteStorage struct {
	sqliteFile string
	sqliteDb   *sql.DB
}

func NewSqliteStorage(sqliteFile string) (storage.Storage, error) {
	db, err := sql.Open("sqlite3", sqliteFile)
	db.SetMaxIdleConns(10)
	db.SetMaxOpenConns(10)
	if err != nil {
		return nil, err
	}
	_, err = db.Exec("PRAGMA foreign_keys = ON;")
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	_, err = db.Exec("PRAGMA journal_mode = WAL;")
	if err != nil {
		_ = db.Close()
		return nil, err
	}

	// check if we have users table. If we don't, we have to execute sqlInit
	res, err := db.Query("select count(*) from sqlite_master where type='table' and name='users'")
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	var count = 0
	if res.Next() {
		err = res.Scan(&count)
		if err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	_ = res.Close()
	if count == 0 {
		_, err = db.Exec(sqlInit)
		if err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	return &sqliteStorage{sqliteDb: db, sqliteFile: sqliteFile}, nil

}

func (s *sqliteStorage) FetchOrCreateUser(ecdsaPublicKeyBytes []byte, initialRsaKeyBytes []byte) (*storage.User, error) {
	res, err := s.sqliteDb.Query("SELECT * FROM users WHERE ecdsa_pub = ?", ecdsaPublicKeyBytes)
	defer func() {
		if res != nil {
			_ = res.Close()
		}
	}()
	if err != nil {
		return nil, err
	}
	if res.Next() {
		user := storage.User{}
		var userId int64
		err = res.Scan(&userId, &user.Username, &user.SearchByUsernameAllowed, &user.EcdsaPublicKeyBytes, &user.InitialRsaKeyBytes)
		user.UserId = ByteInt64ToUint64(userId)
		if err != nil {
			return nil, err
		}
		return &user, nil
	} else {
		pub, err := crypto_utils.PublicECDSAKeyFromBytes(ecdsaPublicKeyBytes)
		if err != nil {
			return nil, err
		}

		res_, err := s.sqliteDb.Exec("INSERT INTO users(user_id, ecdsa_pub, rsa_pub) VALUES (?, ?, ?)", Uint64ToByteInt64(crypto_utils.GenerateUserIdByPublicKey(pub)), ecdsaPublicKeyBytes, initialRsaKeyBytes)
		if err != nil {
			return nil, err
		}
		lastInsertId, err := res_.LastInsertId()
		if err != nil {
			return nil, err
		}
		return &storage.User{
			UserId:              ByteInt64ToUint64(lastInsertId),
			EcdsaPublicKeyBytes: ecdsaPublicKeyBytes,
			InitialRsaKeyBytes:  initialRsaKeyBytes,
		}, nil
	}
}

func (s *sqliteStorage) GetUserById(userId uint64) (*storage.User, error) {
	res, err := s.sqliteDb.Query("SELECT * FROM users WHERE user_id = ?", Uint64ToByteInt64(userId))
	defer func() {
		if res != nil {
			_ = res.Close()
		}
	}()
	if err != nil {
		return nil, err
	}
	if res.Next() {
		user := storage.User{}
		var userIdInt64 int64
		err = res.Scan(&userIdInt64, &user.Username, &user.SearchByUsernameAllowed, &user.EcdsaPublicKeyBytes, &user.InitialRsaKeyBytes)
		if err != nil {
			return nil, err
		}
		user.UserId = ByteInt64ToUint64(userIdInt64)
		return &user, nil
	} else {
		return nil, &storage.ErrUserNotFound
	}

}
func (s *sqliteStorage) SearchForUserByUsername(username string) (*storage.User, error) {
	res, err := s.sqliteDb.Query("SELECT * FROM users WHERE username = ?", username)
	defer func() {
		if res != nil {
			_ = res.Close()
		}
	}()
	if err != nil {
		return nil, err
	}

	if res.Next() {
		user := storage.User{}
		var userIdInt64 int64
		err = res.Scan(&userIdInt64, &user.Username, &user.SearchByUsernameAllowed, &user.EcdsaPublicKeyBytes, &user.InitialRsaKeyBytes)
		if err != nil {
			return nil, err
		}
		if !user.SearchByUsernameAllowed {
			return nil, nil
		}
		user.UserId = ByteInt64ToUint64(userIdInt64)
		return &user, nil
	} else {
		return nil, nil
	}

}

func (s *sqliteStorage) SetUsernameConfig(userId uint64, username string, searchByUsernameAllowed bool) error {
	res, err := s.sqliteDb.Exec("UPDATE users SET username = ?, search_by_username_allowed = ? WHERE user_id = ?", username, searchByUsernameAllowed, Uint64ToByteInt64(userId))
	if err != nil {
		return err
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return &storage.ErrUserNotFound
	}
	return nil
}
func (s *sqliteStorage) PutNotifications(userId uint64, notifications ...*custom_types.IncomingNotification) error {
	for _, notification := range notifications {
		notificationBytes, err := proto.Marshal(notification.ToProtobuf())
		if err != nil {
			return err
		}
		_, err = s.sqliteDb.Exec("INSERT INTO notifications(notification, user_id) VALUES (?, ?)", notificationBytes, Uint64ToByteInt64(userId))
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *sqliteStorage) FetchAndRemoveNotifications(userId uint64, limit int) ([]*custom_types.IncomingNotification, error) {
	res, err := s.sqliteDb.Query("SELECT notification_id, notification FROM notifications WHERE user_id = ? LIMIT ?", Uint64ToByteInt64(userId), limit)
	defer func() {
		if res != nil {
			_ = res.Close()
		}
	}()
	if err != nil {
		return nil, err
	}
	var lastNotificationId int64
	notifications := make([]*custom_types.IncomingNotification, 0, limit)
	for res.Next() {
		var notificationBytes []byte
		err = res.Scan(&lastNotificationId, &notificationBytes)
		if err != nil {
			return nil, err
		}
		var notification = &messages.IncomingNotification{}
		err = proto.Unmarshal(notificationBytes, notification)
		if err != nil {
			return nil, err
		}
		notifications = append(notifications, custom_types.IncomingNotificationFromProtobuf(notification))
	}
	_, err = s.sqliteDb.Exec("DELETE FROM notifications WHERE user_id = ? AND notification_id <= ?", Uint64ToByteInt64(userId), lastNotificationId)
	if err != nil {
		return nil, err
	}
	return notifications, nil
}

func (s *sqliteStorage) CreateChat(initiatorId uint64, receiverId uint64) (*storage.Chat, *storage.User, *storage.User, error) {
	initiator, err := s.GetUserById(initiatorId)
	if err != nil {
		return nil, nil, nil, err
	}
	receiver, err := s.GetUserById(receiverId)
	if err != nil {
		return nil, nil, nil, err
	}
	res, err := s.sqliteDb.Exec("INSERT INTO chats(initiator_id, receiver_id, state) VALUES (?, ?, ?)", Uint64ToByteInt64(initiatorId), Uint64ToByteInt64(receiverId), storage.ChatStateInitiatorRequested)
	if err != nil {
		return nil, nil, nil, err
	}
	lastInsertId, err := res.LastInsertId()
	if err != nil {
		return nil, nil, nil, err
	}
	return &storage.Chat{
		CreatedAt:   time.Now(),
		ChatId:      ByteInt64ToUint64(lastInsertId),
		InitiatorId: initiatorId,
		ReceiverId:  receiverId,
		State:       storage.ChatStateInitiatorRequested,
	}, initiator, receiver, nil
}

func (s *sqliteStorage) GetChat(chatId uint64) (*storage.Chat, error) {
	res, err := s.sqliteDb.Query("SELECT chat_id, created_at, initiator_id, receiver_id, state FROM chats WHERE chat_id = ?", Uint64ToByteInt64(chatId))
	defer func() {
		if res != nil {
			_ = res.Close()
		}
	}()
	if err != nil {
		return nil, err
	}
	if res.Next() {
		chat := storage.Chat{}
		var chatIdInt64, initiatorIdInt64, receiverIdInt64 int64
		err = res.Scan(&chatIdInt64, &chat.CreatedAt, &initiatorIdInt64, &receiverIdInt64, &chat.State)
		if err != nil {
			return nil, err
		}
		chat.ChatId = ByteInt64ToUint64(chatIdInt64)
		chat.InitiatorId = ByteInt64ToUint64(initiatorIdInt64)
		chat.ReceiverId = ByteInt64ToUint64(receiverIdInt64)
		return &chat, nil
	} else {
		return nil, &storage.ErrChatNotFound
	}
}

func (s *sqliteStorage) GetChatByUsers(userA uint64, userB uint64) (*storage.Chat, error) {
	res, err := s.sqliteDb.Query("SELECT chat_id, created_at, initiator_id, receiver_id, state FROM chats WHERE initiator_id = ? AND receiver_id = ?", Uint64ToByteInt64(userA), Uint64ToByteInt64(userB))
	defer func() {
		if res != nil {
			_ = res.Close()
		}
	}()
	if err != nil {
		return nil, err
	}
	if res.Next() {
		chat := storage.Chat{}
		var chatId int64
		var chatIdInt64, initiatorIdInt64, receiverIdInt64 int64
		err = res.Scan(&chatIdInt64, &chat.CreatedAt, &initiatorIdInt64, &receiverIdInt64, &chat.State)
		if err != nil {
			return nil, err
		}
		chat.ChatId = ByteInt64ToUint64(chatId)
		chat.InitiatorId = ByteInt64ToUint64(initiatorIdInt64)
		chat.ReceiverId = ByteInt64ToUint64(receiverIdInt64)
		return &chat, nil
	} else {
		return nil, &storage.ErrChatNotFound
	}
}
func (s *sqliteStorage) UpdateChatState(chatId uint64, state storage.ChatState) error {
	res, err := s.sqliteDb.Exec("UPDATE chats SET state = ? WHERE chat_id = ?", state, Uint64ToByteInt64(chatId))
	if err != nil {
		return err
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return &storage.ErrChatNotFound
	}
	return nil

}

func (s *sqliteStorage) DestroyChat(chatId uint64) error {
	res, err := s.sqliteDb.Exec("DELETE FROM chats WHERE chat_id = ?", Uint64ToByteInt64(chatId))
	if err != nil {
		return err
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return &storage.ErrChatNotFound
	}
	return nil
}
func (s *sqliteStorage) GetNextMessageId(chatId uint64) (uint64, error) {
	// gets next message id and increments it
	res, err := s.sqliteDb.Exec("UPDATE chats SET last_message_id = last_message_id + 1 WHERE chat_id = ?", Uint64ToByteInt64(chatId))
	if err != nil {
		return 0, err
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if rowsAffected == 0 {
		return 0, &storage.ErrChatNotFound
	}
	res2, err := s.sqliteDb.Query("SELECT last_message_id FROM chats WHERE chat_id = ?", Uint64ToByteInt64(chatId))
	defer func() {
		if res != nil {
			_ = res2.Close()
		}
	}()
	if err != nil {
		return 0, err
	}
	if res2.Next() {
		var lastMessageId int64
		err = res2.Scan(&lastMessageId)
		if err != nil {
			return 0, err
		}
		return ByteInt64ToUint64(lastMessageId), nil
	} else {
		return 0, &storage.ErrChatNotFound
	}

}
