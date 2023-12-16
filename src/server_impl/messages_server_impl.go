package server_impl

import (
	"fmt"
	"github.com/apepenkov/sigilix_messenger_server/custom_types"
	"github.com/apepenkov/sigilix_messenger_server/storage"
)

import (
	"context"
)

func (s *ServerImpl) InitChatFromInitializer(ctx context.Context, TargetUserId uint64) (*custom_types.InitChatFromInitializerResponse, *Error) {
	userId := ctx.Value(ContextKeyUser).(uint64)
	reqId := ctx.Value(ContextKeyId).(string)

	created, creator, _, err := s.Storage.CreateChat(userId, TargetUserId)
	if err != nil {
		s.Logger.Errorf("[%s] failed to create chat: %v", reqId, err)
		//return nil, status.Errorf(codes.Internal, "failed to create chat: %v", err)
		return nil, &Error{ErrInternal, "failed to create chat"}
	}

	err = s.Storage.PutNotifications(
		TargetUserId,
		&custom_types.IncomingNotification{
			Notification: &custom_types.InitChatFromInitializerNotification{
				ChatId:              created.ChatId,
				InitializerUserInfo: creator.ToPublicInfo(),
			},
		},
	)

	if err != nil {
		s.Logger.Errorf("[%s] failed to put notification: %v, chat was removed.", reqId, err)
		_ = s.Storage.DestroyChat(created.ChatId)
		//return nil, status.Errorf(codes.Internal, "failed to put notification: %v, chat was removed.", err)
		return nil, &Error{ErrInternal, "failed to put notification"}
	}

	return &custom_types.InitChatFromInitializerResponse{ChatId: created.ChatId}, nil
}

func (s *ServerImpl) InitChatFromReceiver(ctx context.Context, chatId uint64) (*custom_types.InitChatFromReceiverResponse, *Error) {
	userId := ctx.Value(ContextKeyUser).(uint64)
	reqId := ctx.Value(ContextKeyId).(string)

	chat, err := s.Storage.GetChat(chatId)
	if err != nil {
		s.Logger.Errorf("[%s] failed to get chat: %v", reqId, err)
		//return nil, status.Errorf(codes.NotFound, "chat does not exist")
		return nil, &Error{ErrNotFound, "chat does not exist"}
	}

	if chat.ReceiverId != userId {
		s.Logger.Warningf("[%s] user is not a receiver of this chat", reqId)
		//return nil, status.Errorf(codes.PermissionDenied, "user is not a receiver of this chat")
		return nil, &Error{ErrPermissionDenied, "user is not a receiver of this chat"}
	}

	if chat.State != storage.ChatStateInitiatorRequested {
		s.Logger.Warningf("[%s] chat is not in initiator requested state. Maybe it was already accepted?", reqId)
		//return nil, status.Errorf(codes.PermissionDenied, "chat is not in initiator requested state. Maybe it was already accepted?")
		return nil, &Error{ErrPermissionDenied, "chat is not in initiator requested state. Maybe it was already accepted?"}
	}

	err = s.Storage.UpdateChatState(chat.ChatId, storage.ChatStateReceiverAccepted)

	if err != nil {
		s.Logger.Errorf("[%s] failed to update chat state: %v", reqId, err)
		//return nil, status.Errorf(codes.Internal, "failed to update chat state: %v", err)
		return nil, &Error{ErrInternal, "failed to update chat state"}
	}

	receiver, err := s.Storage.GetUserById(userId)
	if err != nil {
		s.Logger.Errorf("[%s] failed to get receiver: %v", reqId, err)
		//return nil, status.Errorf(codes.Internal, "failed to get receiver: %v", err)
		return nil, &Error{ErrInternal, "failed to get receiver"}
	}

	err = s.Storage.PutNotifications(
		chat.InitiatorId,
		&custom_types.IncomingNotification{
			Notification: &custom_types.InitChatFromReceiverNotification{
				ChatId:           chat.ChatId,
				ReceiverUserInfo: receiver.ToPublicInfo(),
			},
		},
	)

	if err != nil {
		s.Logger.Errorf("[%s] failed to put notification: %v, chat was removed.", reqId, err)
		_ = s.Storage.DestroyChat(chat.ChatId)
		//return nil, status.Errorf(codes.Internal, "failed to put notification: %v, chat was removed.", err)
		return nil, &Error{ErrInternal, "failed to put notification"}
	}

	return &custom_types.InitChatFromReceiverResponse{ChatId: chat.ChatId}, nil
}
func (s *ServerImpl) UpdateChatRsaKey(ctx context.Context, chatId uint64, RsaPublicKey []byte) (*custom_types.UpdateChatRsaKeyResponse, *Error) {
	userId := ctx.Value(ContextKeyUser).(uint64)
	reqId := ctx.Value(ContextKeyId).(string)

	chat, err := s.Storage.GetChat(chatId)
	if err != nil {
		s.Logger.Errorf("[%s] failed to get chat: %v", reqId, err)
		//return nil, status.Errorf(codes.NotFound, "chat does not exist")
		return nil, &Error{ErrNotFound, "chat does not exist"}
	}

	if userId != chat.InitiatorId && userId != chat.ReceiverId {
		s.Logger.Warningf("[%s] user is not a member of this chat", reqId)
		//return nil, status.Errorf(codes.PermissionDenied, "user is not a member of this chat")
		return nil, &Error{ErrPermissionDenied, "user is not a member of this chat"}
	}

	sendTo := chat.InitiatorId
	if userId == chat.InitiatorId {
		sendTo = chat.ReceiverId
	}

	err = s.Storage.PutNotifications(
		sendTo,
		&custom_types.IncomingNotification{
			Notification: &custom_types.UpdateChatRsaKeyNotification{
				UserId:       userId,
				ChatId:       chatId,
				RsaPublicKey: RsaPublicKey,
			},
		},
	)

	if err != nil {
		s.Logger.Errorf("[%s] failed to put notification: %v, rsa key update was not sent.", reqId, err)
		//return nil, status.Errorf(codes.Internal, "failed to put notification: %v, rsa key update was not sent.", err)
		return nil, &Error{ErrInternal, "failed to put notification"}
	}

	return &custom_types.UpdateChatRsaKeyResponse{ChatId: chat.ChatId}, nil
}
func (s *ServerImpl) SendMessage(ctx context.Context, ChatId uint64, EncryptedMessage []byte, MessageEcdsaSignature []byte) (*custom_types.SendMessageResponse, *Error) {
	userId := ctx.Value(ContextKeyUser).(uint64)
	reqId := ctx.Value(ContextKeyId).(string)

	destChat, err := s.Storage.GetChat(ChatId)
	if err != nil {
		s.Logger.Errorf("[%s] failed to get chat: %v", reqId, err)
		//return nil, status.Errorf(codes.NotFound, "chat does not exist")
		return nil, &Error{ErrNotFound, "chat does not exist"}
	}

	if userId != destChat.InitiatorId && userId != destChat.ReceiverId {
		s.Logger.Warningf("[%s] user is not a member of this chat", reqId)
		//return nil, status.Errorf(codes.PermissionDenied, "user is not a member of this chat")
		return nil, &Error{ErrPermissionDenied, "user is not a member of this chat"}
	}

	targetUserId := destChat.InitiatorId
	if userId == destChat.InitiatorId {
		targetUserId = destChat.ReceiverId
	}

	messageId, err := s.Storage.GetNextMessageId(ChatId)

	if err != nil {
		s.Logger.Errorf("[%s] failed to get next message id: %v", reqId, err)
		//return nil, status.Errorf(codes.Internal, "failed to get next message id: %v", err)
		return nil, &Error{ErrInternal, "failed to get next message id"}
	}

	err = s.Storage.PutNotifications(
		targetUserId,
		&custom_types.IncomingNotification{
			Notification: &custom_types.SendMessageNotification{
				ChatId:                ChatId,
				MessageId:             messageId,
				SenderUserId:          userId,
				EncryptedMessage:      EncryptedMessage,
				MessageEcdsaSignature: MessageEcdsaSignature,
			},
		},
	)

	if err != nil {
		s.Logger.Errorf("[%s] failed to put notification: %v, message was not sent.", reqId, err)
		//return nil, status.Errorf(codes.Internal, "failed to put notification: %v, message was not sent.", err)
		return nil, &Error{ErrInternal, "failed to put notification"}
	}

	return &custom_types.SendMessageResponse{ChatId: ChatId, MessageId: messageId}, nil
}
func (s *ServerImpl) SendFile(ctx context.Context, ChatId uint64, EncryptedFile []byte, EncryptedMimeType []byte, FileEcdsaSignature []byte) (*custom_types.SendFileResponse, *Error) {
	userId := ctx.Value(ContextKeyUser).(uint64)
	reqId := ctx.Value(ContextKeyId).(string)

	destChat, err := s.Storage.GetChat(ChatId)
	if err != nil {
		s.Logger.Errorf("[%s] failed to get chat: %v", reqId, err)
		//return nil, status.Errorf(codes.NotFound, "chat does not exist")
		return nil, &Error{ErrNotFound, "chat does not exist"}
	}

	if userId != destChat.InitiatorId && userId != destChat.ReceiverId {
		s.Logger.Warningf("[%s] user is not a member of this chat", reqId)
		//return nil, status.Errorf(codes.PermissionDenied, "user is not a member of this chat")
		return nil, &Error{ErrPermissionDenied, "user is not a member of this chat"}
	}

	targetUserId := destChat.InitiatorId
	if userId == destChat.InitiatorId {
		targetUserId = destChat.ReceiverId
	}

	messageId, err := s.Storage.GetNextMessageId(ChatId)

	if err != nil {
		s.Logger.Errorf("[%s] failed to get next message id: %v", reqId, err)
		//return nil, status.Errorf(codes.Internal, "failed to get next message id: %v", err)
		return nil, &Error{ErrInternal, "failed to get next message id"}
	}

	err = s.Storage.PutNotifications(
		targetUserId,
		&custom_types.IncomingNotification{
			Notification: &custom_types.SendFileNotification{
				ChatId:             ChatId,
				MessageId:          messageId,
				SenderUserId:       userId,
				EncryptedFile:      EncryptedFile,
				EncryptedMimeType:  EncryptedMimeType,
				FileEcdsaSignature: FileEcdsaSignature,
			},
		},
	)

	if err != nil {
		s.Logger.Errorf("[%s] failed to put notification: %v, message was not sent.", reqId, err)
		//return nil, status.Errorf(codes.Internal, "failed to put notification: %v, message was not sent.", err)
		return nil, &Error{ErrInternal, "failed to put notification"}
	}

	return &custom_types.SendFileResponse{ChatId: ChatId, MessageId: messageId}, nil
}

func (s *ServerImpl) GetNotifications(ctx context.Context, Limit uint32) (*custom_types.GetNotificationsResponse, *Error) {
	userId := ctx.Value(ContextKeyUser).(uint64)
	reqId := ctx.Value(ContextKeyId).(string)

	if Limit <= 0 {
		s.Logger.Errorf("[%s] invalid limit: %d", reqId, Limit)
		//return nil, status.Errorf(codes.InvalidArgument, "invalid limit: %d", getNotificationsRequest.Limit)
		return nil, &Error{ErrCodeUnknown, fmt.Sprintf("invalid limit: %d", Limit)}
	}

	notifications, err := s.Storage.FetchAndRemoveNotifications(userId, int(Limit))
	if err != nil {
		s.Logger.Errorf("[%s] failed to fetch notifications: %v", reqId, err)
		//return nil, status.Errorf(codes.Internal, "failed to fetch notifications: %v", err)
		return nil, &Error{ErrInternal, fmt.Sprintf("failed to fetch notifications: %v", err)}
	}

	return &custom_types.GetNotificationsResponse{Notifications: notifications}, nil
}
