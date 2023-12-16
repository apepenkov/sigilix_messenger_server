package custom_types

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/apepenkov/sigilix_messenger_server/proto/messages"
	"github.com/apepenkov/sigilix_messenger_server/proto/users"
	"google.golang.org/protobuf/proto"
)

type NotificationType string

const (
	notificationTypeInitChatFromInitializer NotificationType = "InitChatFromInitializer"
	notificationTypeInitChatFromReceiver    NotificationType = "InitChatFromReceiver"
	notificationTypeUpdateChatRsaKey        NotificationType = "UpdateChatRsaKey"
	notificationTypeSendMessage             NotificationType = "SendMessage"
	notificationTypeSendFile                NotificationType = "SendFile"
)

type Base64Bytes []byte

type Protobuffable interface {
	ToProtobuf() proto.Message
}

type SomeNotification interface {
	NotificationType() NotificationType
}

type PublicUserInfo struct {
	UserId              uint64      `json:"user_id"`
	EcdsaPublicKey      Base64Bytes `json:"ecdsa_public_key"`
	Username            string      `json:"username"`
	InitialRsaPublicKey Base64Bytes `json:"initial_rsa_public_key"`
}

func (p *PublicUserInfo) ToProtobuf() proto.Message {
	return &users.PublicUserInfo{
		UserId:              p.UserId,
		EcdsaPublicKey:      p.EcdsaPublicKey,
		Username:            p.Username,
		InitialRsaPublicKey: p.InitialRsaPublicKey,
	}
}

type PrivateUserInfo struct {
	PublicInfo              *PublicUserInfo `json:"public_info"`
	SearchByUsernameAllowed bool            `json:"search_by_username_allowed"`
}

func (p *PrivateUserInfo) ToProtobuf() proto.Message {
	return &users.PrivateUserInfo{
		PublicInfo:              p.PublicInfo.ToProtobuf().(*users.PublicUserInfo),
		SearchByUsernameAllowed: p.SearchByUsernameAllowed,
	}
}

type LoginRequest struct {
	ClientEcdaPublicKey Base64Bytes `json:"client_ecdsa_public_key"`
	ClientRsaPublicKey  Base64Bytes `json:"client_rsa_public_key"`
}

func (l *LoginRequest) ToProtobuf() proto.Message {
	return &users.LoginRequest{
		ClientEcdsaPublicKey: l.ClientEcdaPublicKey,
		ClientRsaPublicKey:   l.ClientRsaPublicKey,
	}
}

type LoginResponse struct {
	PrivateInfo          *PrivateUserInfo `json:"private_info"`
	UserId               uint64           `json:"user_id"`
	ServerEcdsaPublicKey Base64Bytes      `json:"server_ecdsa_public_key"`
}

func (l *LoginResponse) ToProtobuf() proto.Message {
	return &users.LoginResponse{
		PrivateInfo:          l.PrivateInfo.ToProtobuf().(*users.PrivateUserInfo),
		UserId:               l.UserId,
		ServerEcdsaPublicKey: l.ServerEcdsaPublicKey,
	}
}

type SetUsernameConfigRequest struct {
	Username                string `json:"username"`
	SearchByUsernameAllowed bool   `json:"search_by_username_allowed"`
}

func (s *SetUsernameConfigRequest) ToProtobuf() proto.Message {
	return &users.SetUsernameConfigRequest{
		Username:                s.Username,
		SearchByUsernameAllowed: s.SearchByUsernameAllowed,
	}
}

type SetUsernameConfigResponse struct {
	Success bool `json:"success"`
}

func (s *SetUsernameConfigResponse) ToProtobuf() proto.Message {
	return &users.SetUsernameConfigResponse{
		Success: s.Success,
	}
}

type SearchByUsernameRequest struct {
	Username string `json:"username"`
}

func (s *SearchByUsernameRequest) ToProtobuf() proto.Message {
	return &users.SearchByUsernameRequest{
		Username: s.Username,
	}
}

type SearchByUsernameResponse struct {
	PublicInfo *PublicUserInfo `json:"public_info"`
}

func (s *SearchByUsernameResponse) ToProtobuf() proto.Message {
	return &users.SearchByUsernameResponse{
		PublicInfo: s.PublicInfo.ToProtobuf().(*users.PublicUserInfo),
	}
}

// messages

type InitChatFromInitializerRequest struct {
	TargetUserId uint64 `json:"target_user_id"`
}

func (i *InitChatFromInitializerRequest) ToProtobuf() proto.Message {
	return &messages.InitChatFromInitializerRequest{
		TargetUserId: i.TargetUserId,
	}
}

type InitChatFromInitializerResponse struct {
	ChatId uint64 `json:"chat_id"`
}

func (i *InitChatFromInitializerResponse) ToProtobuf() proto.Message {
	return &messages.InitChatFromInitializerResponse{
		ChatId: i.ChatId,
	}
}

type InitChatFromInitializerNotification struct {
	ChatId              uint64          `json:"chat_id"`
	InitializerUserInfo *PublicUserInfo `json:"initializer_user_info"`
}

func (i *InitChatFromInitializerNotification) NotificationType() NotificationType {
	return notificationTypeInitChatFromInitializer
}

func (i *InitChatFromInitializerNotification) ToProtobuf() proto.Message {
	return &messages.InitChatFromInitializerNotification{
		ChatId:              i.ChatId,
		InitializerUserInfo: i.InitializerUserInfo.ToProtobuf().(*users.PublicUserInfo),
	}
}

type InitChatFromReceiverRequest struct {
	ChatId uint64 `json:"chat_id"`
}

func (i *InitChatFromReceiverRequest) ToProtobuf() proto.Message {
	return &messages.InitChatFromReceiverRequest{
		ChatId: i.ChatId,
	}
}

type InitChatFromReceiverResponse struct {
	ChatId uint64 `json:"chat_id"`
}

func (i *InitChatFromReceiverResponse) ToProtobuf() proto.Message {
	return &messages.InitChatFromReceiverResponse{
		ChatId: i.ChatId,
	}
}

type InitChatFromReceiverNotification struct {
	ChatId           uint64          `json:"chat_id"`
	ReceiverUserInfo *PublicUserInfo `json:"receiver_user_info"`
}

func (i *InitChatFromReceiverNotification) NotificationType() NotificationType {
	return notificationTypeInitChatFromReceiver
}

func (i *InitChatFromReceiverNotification) ToProtobuf() proto.Message {
	return &messages.InitChatFromReceiverNotification{
		ChatId:           i.ChatId,
		ReceiverUserInfo: i.ReceiverUserInfo.ToProtobuf().(*users.PublicUserInfo),
	}
}

type UpdateChatRsaKeyRequest struct {
	ChatId       uint64      `json:"chat_id"`
	RsaPublicKey Base64Bytes `json:"rsa_public_key"`
}

func (u *UpdateChatRsaKeyRequest) ToProtobuf() proto.Message {
	return &messages.UpdateChatRsaKeyRequest{
		ChatId:       u.ChatId,
		RsaPublicKey: u.RsaPublicKey,
	}
}

type UpdateChatRsaKeyResponse struct {
	ChatId uint64 `json:"chat_id"`
}

func (u *UpdateChatRsaKeyResponse) ToProtobuf() proto.Message {
	return &messages.UpdateChatRsaKeyResponse{
		ChatId: u.ChatId,
	}
}

type UpdateChatRsaKeyNotification struct {
	ChatId       uint64      `json:"chat_id"`
	UserId       uint64      `json:"user_id"`
	RsaPublicKey Base64Bytes `json:"rsa_public_key"`
}

func (u *UpdateChatRsaKeyNotification) NotificationType() NotificationType {
	return notificationTypeUpdateChatRsaKey
}

func (u *UpdateChatRsaKeyNotification) ToProtobuf() proto.Message {
	return &messages.UpdateChatRsaKeyNotification{
		ChatId:       u.ChatId,
		UserId:       u.UserId,
		RsaPublicKey: u.RsaPublicKey,
	}
}

type SendMessageRequest struct {
	ChatId                uint64      `json:"chat_id"`
	EncryptedMessage      Base64Bytes `json:"encrypted_message"`
	MessageEcdsaSignature Base64Bytes `json:"message_ecdsa_signature"`
}

func (s *SendMessageRequest) ToProtobuf() proto.Message {
	return &messages.SendMessageRequest{
		ChatId:                s.ChatId,
		EncryptedMessage:      s.EncryptedMessage,
		MessageEcdsaSignature: s.MessageEcdsaSignature,
	}
}

type SendMessageResponse struct {
	ChatId    uint64 `json:"chat_id"`
	MessageId uint64 `json:"message_id"`
}

func (s *SendMessageResponse) ToProtobuf() proto.Message {
	return &messages.SendMessageResponse{
		ChatId:    s.ChatId,
		MessageId: s.MessageId,
	}
}

type SendMessageNotification struct {
	ChatId                uint64      `json:"chat_id"`
	MessageId             uint64      `json:"message_id"`
	SenderUserId          uint64      `json:"sender_user_id"`
	EncryptedMessage      Base64Bytes `json:"encrypted_message"`
	MessageEcdsaSignature Base64Bytes `json:"message_ecdsa_signature"`
}

func (s *SendMessageNotification) NotificationType() NotificationType {
	return notificationTypeSendMessage
}

func (s *SendMessageNotification) ToProtobuf() proto.Message {
	return &messages.SendMessageNotification{
		ChatId:                s.ChatId,
		MessageId:             s.MessageId,
		SenderUserId:          s.SenderUserId,
		EncryptedMessage:      s.EncryptedMessage,
		MessageEcdsaSignature: s.MessageEcdsaSignature,
	}
}

type SendFileRequest struct {
	ChatId             uint64      `json:"chat_id"`
	EncryptedFile      Base64Bytes `json:"encrypted_file"`
	EncryptedMimeType  Base64Bytes `json:"encrypted_mime_type"`
	FileEcdsaSignature Base64Bytes `json:"file_ecdsa_signature"`
}

func (s *SendFileRequest) ToProtobuf() proto.Message {
	return &messages.SendFileRequest{
		ChatId:             s.ChatId,
		EncryptedFile:      s.EncryptedFile,
		EncryptedMimeType:  s.EncryptedMimeType,
		FileEcdsaSignature: s.FileEcdsaSignature,
	}
}

type SendFileResponse struct {
	ChatId    uint64 `json:"chat_id"`
	MessageId uint64 `json:"message_id"`
}

func (s *SendFileResponse) ToProtobuf() proto.Message {
	return &messages.SendFileResponse{
		ChatId:    s.ChatId,
		MessageId: s.MessageId,
	}
}

type SendFileNotification struct {
	ChatId             uint64      `json:"chat_id"`
	MessageId          uint64      `json:"message_id"`
	SenderUserId       uint64      `json:"sender_user_id"`
	EncryptedFile      Base64Bytes `json:"encrypted_file"`
	EncryptedMimeType  Base64Bytes `json:"encrypted_mime_type"`
	FileEcdsaSignature Base64Bytes `json:"file_ecdsa_signature"`
}

func (s *SendFileNotification) NotificationType() NotificationType { return notificationTypeSendFile }

func (s *SendFileNotification) ToProtobuf() proto.Message {
	return &messages.SendFileNotification{
		ChatId:             s.ChatId,
		MessageId:          s.MessageId,
		SenderUserId:       s.SenderUserId,
		EncryptedFile:      s.EncryptedFile,
		EncryptedMimeType:  s.EncryptedMimeType,
		FileEcdsaSignature: s.FileEcdsaSignature,
	}
}

type IncomingNotification struct {
	Notification   SomeNotification `json:"notification"`
	EcdsaSignature Base64Bytes      `json:"ecdsa_signature"`
}

func (i *IncomingNotification) ToProtobuf() proto.Message {
	switch i.Notification.(type) {
	case *InitChatFromInitializerNotification:
		return &messages.IncomingNotification{
			Notification: &messages.IncomingNotification_InitChatFromInitializerNotification{
				InitChatFromInitializerNotification: i.Notification.(*InitChatFromInitializerNotification).ToProtobuf().(*messages.InitChatFromInitializerNotification),
			},
			EcdsaSignature: i.EcdsaSignature,
		}
	case *InitChatFromReceiverNotification:
		return &messages.IncomingNotification{
			Notification: &messages.IncomingNotification_InitChatFromReceiverNotification{
				InitChatFromReceiverNotification: i.Notification.(*InitChatFromReceiverNotification).ToProtobuf().(*messages.InitChatFromReceiverNotification),
			},
			EcdsaSignature: i.EcdsaSignature,
		}
	case *UpdateChatRsaKeyNotification:
		return &messages.IncomingNotification{
			Notification: &messages.IncomingNotification_UpdateChatRsaKeyNotification{
				UpdateChatRsaKeyNotification: i.Notification.(*UpdateChatRsaKeyNotification).ToProtobuf().(*messages.UpdateChatRsaKeyNotification),
			},
			EcdsaSignature: i.EcdsaSignature,
		}
	case *SendMessageNotification:
		return &messages.IncomingNotification{
			Notification: &messages.IncomingNotification_SendMessageNotification{
				SendMessageNotification: i.Notification.(*SendMessageNotification).ToProtobuf().(*messages.SendMessageNotification),
			},
			EcdsaSignature: i.EcdsaSignature,
		}
	case *SendFileNotification:
		return &messages.IncomingNotification{
			Notification: &messages.IncomingNotification_SendFileNotification{
				SendFileNotification: i.Notification.(*SendFileNotification).ToProtobuf().(*messages.SendFileNotification),
			},
			EcdsaSignature: i.EcdsaSignature,
		}
	default:
		return nil
	}
}

func IncomingNotificationFromProtobuf(notification *messages.IncomingNotification) *IncomingNotification {
	switch notification.Notification.(type) {
	case *messages.IncomingNotification_InitChatFromInitializerNotification:
		return &IncomingNotification{
			Notification: &InitChatFromInitializerNotification{
				ChatId:              notification.GetInitChatFromInitializerNotification().ChatId,
				InitializerUserInfo: PublicUserInfoFromProtobuf(notification.GetInitChatFromInitializerNotification().InitializerUserInfo),
			},
			EcdsaSignature: notification.GetEcdsaSignature(),
		}
	case *messages.IncomingNotification_InitChatFromReceiverNotification:
		return &IncomingNotification{
			Notification: &InitChatFromReceiverNotification{
				ChatId:           notification.GetInitChatFromReceiverNotification().ChatId,
				ReceiverUserInfo: PublicUserInfoFromProtobuf(notification.GetInitChatFromReceiverNotification().ReceiverUserInfo),
			},
			EcdsaSignature: notification.GetEcdsaSignature(),
		}
	case *messages.IncomingNotification_UpdateChatRsaKeyNotification:
		return &IncomingNotification{
			Notification: &UpdateChatRsaKeyNotification{
				ChatId:       notification.GetUpdateChatRsaKeyNotification().ChatId,
				UserId:       notification.GetUpdateChatRsaKeyNotification().UserId,
				RsaPublicKey: notification.GetUpdateChatRsaKeyNotification().RsaPublicKey,
			},
			EcdsaSignature: notification.GetEcdsaSignature(),
		}
	case *messages.IncomingNotification_SendMessageNotification:
		return &IncomingNotification{
			Notification: &SendMessageNotification{
				ChatId:                notification.GetSendMessageNotification().ChatId,
				MessageId:             notification.GetSendMessageNotification().MessageId,
				SenderUserId:          notification.GetSendMessageNotification().SenderUserId,
				EncryptedMessage:      notification.GetSendMessageNotification().EncryptedMessage,
				MessageEcdsaSignature: notification.GetSendMessageNotification().MessageEcdsaSignature,
			},
			EcdsaSignature: notification.GetEcdsaSignature(),
		}
	case *messages.IncomingNotification_SendFileNotification:
		return &IncomingNotification{
			Notification: &SendFileNotification{
				ChatId:             notification.GetSendFileNotification().ChatId,
				MessageId:          notification.GetSendFileNotification().MessageId,
				SenderUserId:       notification.GetSendFileNotification().SenderUserId,
				EncryptedFile:      notification.GetSendFileNotification().EncryptedFile,
				EncryptedMimeType:  notification.GetSendFileNotification().EncryptedMimeType,
				FileEcdsaSignature: notification.GetSendFileNotification().FileEcdsaSignature,
			},
			EcdsaSignature: notification.GetEcdsaSignature(),
		}
	default:
		return nil
	}
}

type NotificationWithTypeInfo struct {
	Notification SomeNotification `json:"notif"`
	Type         NotificationType `json:"type"`
}

func (i *IncomingNotification) MarshalJSON() ([]byte, error) {
	r := &NotificationWithTypeInfo{
		Notification: i.Notification,
		Type:         i.Notification.NotificationType(),
	}
	return json.Marshal(r)
}

func PublicUserInfoFromProtobuf(userInfo *users.PublicUserInfo) *PublicUserInfo {
	return &PublicUserInfo{
		UserId:              userInfo.UserId,
		EcdsaPublicKey:      userInfo.EcdsaPublicKey,
		Username:            userInfo.Username,
		InitialRsaPublicKey: userInfo.InitialRsaPublicKey,
	}
}

type GetNotificationsRequest struct {
	Limit uint32 `json:"limit"`
}

func (g *GetNotificationsRequest) ToProtobuf() proto.Message {
	return &messages.GetNotificationsRequest{
		Limit: g.Limit,
	}
}

type GetNotificationsResponse struct {
	Notifications []*IncomingNotification `json:"notifications"`
}

func (g *GetNotificationsResponse) ToProtobuf() proto.Message {
	notifications := make([]*messages.IncomingNotification, len(g.Notifications))
	for i, n := range g.Notifications {
		notifications[i] = n.ToProtobuf().(*messages.IncomingNotification)
	}
	return &messages.GetNotificationsResponse{
		Notifications: notifications,
	}
}

func (b *Base64Bytes) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%s\"", base64.StdEncoding.EncodeToString(*b))), nil
}

func (b *Base64Bytes) UnmarshalJSON(data []byte) error {
	// Remove the quotes from the JSON string
	str := string(data[1 : len(data)-1])

	// Decode from base64
	decoded, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return err
	}

	*b = decoded
	return nil
}
