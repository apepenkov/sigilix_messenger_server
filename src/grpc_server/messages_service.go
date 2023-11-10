package grpc_server

import (
	"context"
	"github.com/apepenkov/sigilix_messenger_server/proto/messages"
	"github.com/apepenkov/sigilix_messenger_server/storage"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"time"
)

type messagesService struct {
	storage              storage.Storage
	serverECDSAPublicKey []byte
	messages.UnimplementedMessageServiceServer
}

func (ms *messagesService) InitChatFromInitializer(ctx context.Context, initChatFromInitializerRequest *messages.InitChatFromInitializerRequest) (*messages.InitChatFromInitializerResponse, error) {
	userId := ctx.Value(userContextKey).(uint64)

	created, creator, _, err := ms.storage.CreateChat(userId, initChatFromInitializerRequest.TargetUserId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create chat: %v", err)
	}

	err = ms.storage.PutNotifications(
		initChatFromInitializerRequest.TargetUserId,
		&messages.IncomingNotification{
			Notification: &messages.IncomingNotification_InitChatFromInitializerNotification{
				InitChatFromInitializerNotification: &messages.InitChatFromInitializerNotification{
					ChatId:              created.ChatId,
					InitializerUserInfo: creator.ToPublicInfo(),
				},
			},
		},
	)

	if err != nil {
		_ = ms.storage.DestroyChat(created.ChatId)
		return nil, status.Errorf(codes.Internal, "failed to put notification: %v, chat was removed.", err)
	}

	return &messages.InitChatFromInitializerResponse{ChatId: created.ChatId}, nil
}

func (ms *messagesService) InitChatFromReceiver(ctx context.Context, initChatFromReceiverRequest *messages.InitChatFromReceiverRequest) (*messages.InitChatFromReceiverResponse, error) {
	userId := ctx.Value(userContextKey).(uint64)

	chat, err := ms.storage.GetChat(initChatFromReceiverRequest.ChatId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "chat does not exist")
	}

	if chat.ReceiverId != userId {
		return nil, status.Errorf(codes.PermissionDenied, "user is not a receiver of this chat")
	}

	if chat.State != storage.ChatStateInitiatorRequested {
		return nil, status.Errorf(codes.PermissionDenied, "chat is not in initiator requested state. Maybe it was already accepted?")
	}

	err = ms.storage.UpdateChatState(chat.ChatId, storage.ChatStateReceiverAccepted)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update chat state: %v", err)
	}

	receiver, err := ms.storage.GetUserById(userId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get receiver: %v", err)
	}

	err = ms.storage.PutNotifications(
		chat.InitiatorId,
		&messages.IncomingNotification{
			Notification: &messages.IncomingNotification_InitChatFromReceiverNotification{
				InitChatFromReceiverNotification: &messages.InitChatFromReceiverNotification{
					ChatId:           chat.ChatId,
					ReceiverUserInfo: receiver.ToPublicInfo(),
				},
			},
		},
	)

	if err != nil {
		_ = ms.storage.DestroyChat(chat.ChatId)
		return nil, status.Errorf(codes.Internal, "failed to put notification: %v, chat was removed.", err)
	}

	return &messages.InitChatFromReceiverResponse{ChatId: chat.ChatId}, nil
}
func (ms *messagesService) UpdateChatRsaKey(ctx context.Context, updateChatRsaKeyRequest *messages.UpdateChatRsaKeyRequest) (*messages.UpdateChatRsaKeyResponse, error) {
	userId := ctx.Value(userContextKey).(uint64)

	chat, err := ms.storage.GetChat(updateChatRsaKeyRequest.ChatId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "chat does not exist")
	}

	if userId != chat.InitiatorId && userId != chat.ReceiverId {
		return nil, status.Errorf(codes.PermissionDenied, "user is not a member of this chat")
	}

	sendTo := chat.InitiatorId
	if userId == chat.InitiatorId {
		sendTo = chat.ReceiverId
	}

	err = ms.storage.PutNotifications(
		sendTo,
		&messages.IncomingNotification{
			Notification: &messages.IncomingNotification_UpdateChatRsaKeyNotification{
				UpdateChatRsaKeyNotification: &messages.UpdateChatRsaKeyNotification{
					UserId:       userId,
					ChatId:       updateChatRsaKeyRequest.ChatId,
					RsaPublicKey: updateChatRsaKeyRequest.RsaPublicKey,
				},
			},
		},
	)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to put notification: %v, rsa key update was not sent.", err)
	}

	return &messages.UpdateChatRsaKeyResponse{ChatId: chat.ChatId}, nil
}
func (ms *messagesService) SendMessage(ctx context.Context, sendMessageRequest *messages.SendMessageRequest) (*messages.SendMessageResponse, error) {
	userId := ctx.Value(userContextKey).(uint64)

	destChat, err := ms.storage.GetChat(sendMessageRequest.ChatId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "chat does not exist")
	}

	if userId != destChat.InitiatorId && userId != destChat.ReceiverId {
		return nil, status.Errorf(codes.PermissionDenied, "user is not a member of this chat")
	}

	targetUserId := destChat.InitiatorId
	if userId == destChat.InitiatorId {
		targetUserId = destChat.ReceiverId
	}

	messageId, err := ms.storage.GetNextMessageId(sendMessageRequest.ChatId)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get next message id: %v", err)
	}

	err = ms.storage.PutNotifications(
		targetUserId,
		&messages.IncomingNotification{
			Notification: &messages.IncomingNotification_SendMessageNotification{
				SendMessageNotification: &messages.SendMessageNotification{
					ChatId:                sendMessageRequest.ChatId,
					MessageId:             messageId,
					SenderUserId:          userId,
					EncryptedMessage:      sendMessageRequest.EncryptedMessage,
					MessageEcdsaSignature: sendMessageRequest.MessageEcdsaSignature,
				},
			},
		},
	)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to put notification: %v, message was not sent.", err)
	}

	return &messages.SendMessageResponse{ChatId: sendMessageRequest.ChatId, MessageId: messageId}, nil
}
func (ms *messagesService) SendFile(ctx context.Context, sendFileRequest *messages.SendFileRequest) (*messages.SendFileResponse, error) {
	userId := ctx.Value(userContextKey).(uint64)

	destChat, err := ms.storage.GetChat(sendFileRequest.ChatId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "chat does not exist")
	}

	if userId != destChat.InitiatorId && userId != destChat.ReceiverId {
		return nil, status.Errorf(codes.PermissionDenied, "user is not a member of this chat")
	}

	targetUserId := destChat.InitiatorId
	if userId == destChat.InitiatorId {
		targetUserId = destChat.ReceiverId
	}

	messageId, err := ms.storage.GetNextMessageId(sendFileRequest.ChatId)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get next message id: %v", err)
	}

	err = ms.storage.PutNotifications(
		targetUserId,
		&messages.IncomingNotification{
			Notification: &messages.IncomingNotification_SendFileNotification{
				SendFileNotification: &messages.SendFileNotification{
					ChatId:             sendFileRequest.ChatId,
					MessageId:          messageId,
					SenderUserId:       userId,
					EncryptedFile:      sendFileRequest.EncryptedFile,
					EncryptedMimeType:  sendFileRequest.EncryptedMimeType,
					FileEcdsaSignature: sendFileRequest.FileEcdsaSignature,
				},
			},
		},
	)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to put notification: %v, message was not sent.", err)
	}

	return &messages.SendFileResponse{ChatId: sendFileRequest.ChatId, MessageId: messageId}, nil
}
func (ms *messagesService) SubscribeToIncomingNotifications(subReq *messages.SubscriptionRequest, stream messages.MessageService_SubscribeToIncomingNotificationsServer) error {
	ctx := stream.Context()
	userId := ctx.Value(userContextKey).(uint64)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			notifications, err := ms.storage.FetchAndRemoveNotifications(userId, 10)
			if err != nil {
				return status.Errorf(codes.Internal, "failed to fetch notifications: %v", err)
			}
			if len(notifications) == 0 {
				// No new notifications, wait before trying again
				time.Sleep(100 * time.Millisecond)
				continue
			}
			for _, notification := range notifications {
				if err := stream.Send(notification); err != nil {
					// Stream closed or client disconnected
					return err // Directly return the error
				}
			}
		}
	}
}
