package custom_types

import "encoding/json"

type PublicUserInfo struct {
	UserId              uint64      `json:"user_id"`
	EcdsaPublicKey      Base64Bytes `json:"ecdsa_public_key"`
	Username            string      `json:"username"`
	InitialRsaPublicKey Base64Bytes `json:"initial_rsa_public_key"`
}

type PrivateUserInfo struct {
	PublicInfo              *PublicUserInfo `json:"public_info"`
	SearchByUsernameAllowed bool            `json:"search_by_username_allowed"`
}

type LoginRequest struct {
	ClientEcdaPublicKey Base64Bytes `json:"client_ecdsa_public_key"`
	ClientRsaPublicKey  Base64Bytes `json:"client_rsa_public_key"`
}

type LoginResponse struct {
	PrivateInfo          *PrivateUserInfo `json:"private_info"`
	UserId               uint64           `json:"user_id"`
	ServerEcdsaPublicKey Base64Bytes      `json:"server_ecdsa_public_key"`
}

type SetUsernameConfigRequest struct {
	Username                string `json:"username"`
	SearchByUsernameAllowed bool   `json:"search_by_username_allowed"`
}

type SetUsernameConfigResponse struct {
	Success bool `json:"success"`
}

type SearchByUsernameRequest struct {
	Username string `json:"username"`
}

type SearchByUsernameResponse struct {
	PublicInfo *PublicUserInfo `json:"public_info"`
}

type InitChatFromInitializerRequest struct {
	TargetUserId uint64 `json:"target_user_id"`
}

type InitChatFromInitializerResponse struct {
	ChatId uint64 `json:"chat_id"`
}

type InitChatFromInitializerNotification struct {
	ChatId              uint64          `json:"chat_id"`
	InitializerUserInfo *PublicUserInfo `json:"initializer_user_info"`
}

type InitChatFromReceiverRequest struct {
	ChatId uint64 `json:"chat_id"`
}

type InitChatFromReceiverResponse struct {
	ChatId uint64 `json:"chat_id"`
}

type InitChatFromReceiverNotification struct {
	ChatId           uint64          `json:"chat_id"`
	ReceiverUserInfo *PublicUserInfo `json:"receiver_user_info"`
}

type UpdateChatRsaKeyRequest struct {
	ChatId       uint64      `json:"chat_id"`
	RsaPublicKey Base64Bytes `json:"rsa_public_key"`
}

type UpdateChatRsaKeyResponse struct {
	ChatId uint64 `json:"chat_id"`
}
type UpdateChatRsaKeyNotification struct {
	ChatId       uint64      `json:"chat_id"`
	UserId       uint64      `json:"user_id"`
	RsaPublicKey Base64Bytes `json:"rsa_public_key"`
}

type SendMessageRequest struct {
	ChatId                uint64      `json:"chat_id"`
	EncryptedMessage      Base64Bytes `json:"encrypted_message"`
	MessageEcdsaSignature Base64Bytes `json:"message_ecdsa_signature"`
}

type SendMessageResponse struct {
	ChatId    uint64 `json:"chat_id"`
	MessageId uint64 `json:"message_id"`
}
type SendMessageNotification struct {
	ChatId                uint64      `json:"chat_id"`
	MessageId             uint64      `json:"message_id"`
	SenderUserId          uint64      `json:"sender_user_id"`
	EncryptedMessage      Base64Bytes `json:"encrypted_message"`
	MessageEcdsaSignature Base64Bytes `json:"message_ecdsa_signature"`
}
type SendFileRequest struct {
	ChatId             uint64      `json:"chat_id"`
	EncryptedFile      Base64Bytes `json:"encrypted_file"`
	EncryptedMimeType  Base64Bytes `json:"encrypted_mime_type"`
	FileEcdsaSignature Base64Bytes `json:"file_ecdsa_signature"`
}
type SendFileResponse struct {
	ChatId    uint64 `json:"chat_id"`
	MessageId uint64 `json:"message_id"`
}
type SendFileNotification struct {
	ChatId             uint64      `json:"chat_id"`
	MessageId          uint64      `json:"message_id"`
	SenderUserId       uint64      `json:"sender_user_id"`
	EncryptedFile      Base64Bytes `json:"encrypted_file"`
	EncryptedMimeType  Base64Bytes `json:"encrypted_mime_type"`
	FileEcdsaSignature Base64Bytes `json:"file_ecdsa_signature"`
}

type IncomingNotification struct {
	Notification   SomeNotification `json:"notification"`
	EcdsaSignature Base64Bytes      `json:"ecdsa_signature"`
}

type NotificationWithTypeInfo struct {
	Notification SomeNotification `json:"notification"`
	Type         NotificationType `json:"type"`
}

func (i *IncomingNotification) MarshalJSON() ([]byte, error) {
	r := &NotificationWithTypeInfo{
		Notification: i.Notification,
		Type:         i.Notification.NotificationType(),
	}
	return json.Marshal(r)
}

func (i *IncomingNotification) UnmarshalJSON(data []byte) error {
	r := &NotificationWithTypeInfo{}
	err := json.Unmarshal(data, r)
	if err != nil {
		return err
	}
	i.Notification = r.Notification
	return nil
}

type GetNotificationsRequest struct {
	Limit uint32 `json:"limit"`
}

type GetNotificationsResponse struct {
	Notifications []*IncomingNotification `json:"notifications"`
}
