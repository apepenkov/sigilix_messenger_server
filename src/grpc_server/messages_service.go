package grpc_server

import (
	"context"
	"crypto/ecdsa"
	"github.com/apepenkov/sigilix_messenger_server/crypto_utils"
	"github.com/apepenkov/sigilix_messenger_server/logger"
	"github.com/apepenkov/sigilix_messenger_server/proto/messages"
	"github.com/apepenkov/sigilix_messenger_server/storage"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"time"
)

type messagesService struct {
	storage               storage.Storage
	serverECDSAPublicKey  []byte
	serverECDSAPrivateKey *ecdsa.PrivateKey
	logger                *logger.Logger
	messages.UnimplementedMessageServiceServer
}

func (ms *messagesService) InitChatFromInitializer(ctx context.Context, initChatFromInitializerRequest *messages.InitChatFromInitializerRequest) (*messages.InitChatFromInitializerResponse, error) {
	userId := ctx.Value(contextKeyUser).(uint64)
	reqId := ctx.Value(contextKeyId).(string)

	created, creator, _, err := ms.storage.CreateChat(userId, initChatFromInitializerRequest.TargetUserId)
	if err != nil {
		ms.logger.Errorf("[%s] failed to create chat: %v", reqId, err)
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
		ms.logger.Errorf("[%s] failed to put notification: %v, chat was removed.", reqId, err)
		_ = ms.storage.DestroyChat(created.ChatId)
		return nil, status.Errorf(codes.Internal, "failed to put notification: %v, chat was removed.", err)
	}

	return &messages.InitChatFromInitializerResponse{ChatId: created.ChatId}, nil
}

func (ms *messagesService) InitChatFromReceiver(ctx context.Context, initChatFromReceiverRequest *messages.InitChatFromReceiverRequest) (*messages.InitChatFromReceiverResponse, error) {
	userId := ctx.Value(contextKeyUser).(uint64)
	reqId := ctx.Value(contextKeyId).(string)

	chat, err := ms.storage.GetChat(initChatFromReceiverRequest.ChatId)
	if err != nil {
		ms.logger.Errorf("[%s] failed to get chat: %v", reqId, err)
		return nil, status.Errorf(codes.NotFound, "chat does not exist")
	}

	if chat.ReceiverId != userId {
		ms.logger.Warningf("[%s] user is not a receiver of this chat", reqId)
		return nil, status.Errorf(codes.PermissionDenied, "user is not a receiver of this chat")
	}

	if chat.State != storage.ChatStateInitiatorRequested {
		ms.logger.Warningf("[%s] chat is not in initiator requested state. Maybe it was already accepted?", reqId)
		return nil, status.Errorf(codes.PermissionDenied, "chat is not in initiator requested state. Maybe it was already accepted?")
	}

	err = ms.storage.UpdateChatState(chat.ChatId, storage.ChatStateReceiverAccepted)

	if err != nil {
		ms.logger.Errorf("[%s] failed to update chat state: %v", reqId, err)
		return nil, status.Errorf(codes.Internal, "failed to update chat state: %v", err)
	}

	receiver, err := ms.storage.GetUserById(userId)
	if err != nil {
		ms.logger.Errorf("[%s] failed to get receiver: %v", reqId, err)
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
		ms.logger.Errorf("[%s] failed to put notification: %v, chat was removed.", reqId, err)
		_ = ms.storage.DestroyChat(chat.ChatId)
		return nil, status.Errorf(codes.Internal, "failed to put notification: %v, chat was removed.", err)
	}

	return &messages.InitChatFromReceiverResponse{ChatId: chat.ChatId}, nil
}
func (ms *messagesService) UpdateChatRsaKey(ctx context.Context, updateChatRsaKeyRequest *messages.UpdateChatRsaKeyRequest) (*messages.UpdateChatRsaKeyResponse, error) {
	userId := ctx.Value(contextKeyUser).(uint64)
	reqId := ctx.Value(contextKeyId).(string)

	chat, err := ms.storage.GetChat(updateChatRsaKeyRequest.ChatId)
	if err != nil {
		ms.logger.Errorf("[%s] failed to get chat: %v", reqId, err)
		return nil, status.Errorf(codes.NotFound, "chat does not exist")
	}

	if userId != chat.InitiatorId && userId != chat.ReceiverId {
		ms.logger.Warningf("[%s] user is not a member of this chat", reqId)
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
		ms.logger.Errorf("[%s] failed to put notification: %v, rsa key update was not sent.", reqId, err)
		return nil, status.Errorf(codes.Internal, "failed to put notification: %v, rsa key update was not sent.", err)
	}

	return &messages.UpdateChatRsaKeyResponse{ChatId: chat.ChatId}, nil
}
func (ms *messagesService) SendMessage(ctx context.Context, sendMessageRequest *messages.SendMessageRequest) (*messages.SendMessageResponse, error) {
	userId := ctx.Value(contextKeyUser).(uint64)
	reqId := ctx.Value(contextKeyId).(string)

	destChat, err := ms.storage.GetChat(sendMessageRequest.ChatId)
	if err != nil {
		ms.logger.Errorf("[%s] failed to get chat: %v", reqId, err)
		return nil, status.Errorf(codes.NotFound, "chat does not exist")
	}

	if userId != destChat.InitiatorId && userId != destChat.ReceiverId {
		ms.logger.Warningf("[%s] user is not a member of this chat", reqId)
		return nil, status.Errorf(codes.PermissionDenied, "user is not a member of this chat")
	}

	targetUserId := destChat.InitiatorId
	if userId == destChat.InitiatorId {
		targetUserId = destChat.ReceiverId
	}

	messageId, err := ms.storage.GetNextMessageId(sendMessageRequest.ChatId)

	if err != nil {
		ms.logger.Errorf("[%s] failed to get next message id: %v", reqId, err)
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
		ms.logger.Errorf("[%s] failed to put notification: %v, message was not sent.", reqId, err)
		return nil, status.Errorf(codes.Internal, "failed to put notification: %v, message was not sent.", err)
	}

	return &messages.SendMessageResponse{ChatId: sendMessageRequest.ChatId, MessageId: messageId}, nil
}
func (ms *messagesService) SendFile(ctx context.Context, sendFileRequest *messages.SendFileRequest) (*messages.SendFileResponse, error) {
	userId := ctx.Value(contextKeyUser).(uint64)
	reqId := ctx.Value(contextKeyId).(string)

	destChat, err := ms.storage.GetChat(sendFileRequest.ChatId)
	if err != nil {
		ms.logger.Errorf("[%s] failed to get chat: %v", reqId, err)
		return nil, status.Errorf(codes.NotFound, "chat does not exist")
	}

	if userId != destChat.InitiatorId && userId != destChat.ReceiverId {
		ms.logger.Warningf("[%s] user is not a member of this chat", reqId)
		return nil, status.Errorf(codes.PermissionDenied, "user is not a member of this chat")
	}

	targetUserId := destChat.InitiatorId
	if userId == destChat.InitiatorId {
		targetUserId = destChat.ReceiverId
	}

	messageId, err := ms.storage.GetNextMessageId(sendFileRequest.ChatId)

	if err != nil {
		ms.logger.Errorf("[%s] failed to get next message id: %v", reqId, err)
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
		ms.logger.Errorf("[%s] failed to put notification: %v, message was not sent.", reqId, err)
		return nil, status.Errorf(codes.Internal, "failed to put notification: %v, message was not sent.", err)
	}

	return &messages.SendFileResponse{ChatId: sendFileRequest.ChatId, MessageId: messageId}, nil
}
func (ms *messagesService) SubscribeToIncomingNotifications(subReq *messages.SubscriptionRequest, stream messages.MessageService_SubscribeToIncomingNotificationsServer) error {
	ctx := stream.Context()
	userId := ctx.Value(contextKeyUser).(uint64)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			notifications, err := ms.storage.FetchAndRemoveNotifications(userId, 10)
			if err != nil {
				return status.Errorf(codes.Internal, "failed to fetch notifications: %v", err)
			}
			for _, notification := range notifications {
				if err := signAndSendNotification(stream, notification, ms.serverECDSAPrivateKey); err != nil {
					return err // This could be a stream.Send error or signing error
				}
			}
		}
	}
}

func (ms *messagesService) GetNotifications(ctx context.Context, getNotificationsRequest *messages.GetNotificationsRequest) (*messages.GetNotificationsResponse, error) {
	userId := ctx.Value(contextKeyUser).(uint64)
	reqId := ctx.Value(contextKeyId).(string)

	if getNotificationsRequest.Limit <= 0 {
		ms.logger.Errorf("[%s] invalid limit: %d", reqId, getNotificationsRequest.Limit)
		return nil, status.Errorf(codes.InvalidArgument, "invalid limit: %d", getNotificationsRequest.Limit)
	}

	notifications, err := ms.storage.FetchAndRemoveNotifications(userId, int(getNotificationsRequest.Limit))
	if err != nil {
		ms.logger.Errorf("[%s] failed to fetch notifications: %v", reqId, err)
		return nil, status.Errorf(codes.Internal, "failed to fetch notifications: %v", err)
	}

	return &messages.GetNotificationsResponse{Notifications: notifications}, nil
}

func signAndSendNotification(stream messages.MessageService_SubscribeToIncomingNotificationsServer, notification *messages.IncomingNotification, privateKey *ecdsa.PrivateKey) error {

	var marshalled []byte
	var err error
	switch x := notification.Notification.(type) {
	case *messages.IncomingNotification_InitChatFromInitializerNotification:
		marshalled, err = proto.Marshal(x.InitChatFromInitializerNotification)
	case *messages.IncomingNotification_InitChatFromReceiverNotification:
		marshalled, err = proto.Marshal(x.InitChatFromReceiverNotification)
	case *messages.IncomingNotification_UpdateChatRsaKeyNotification:
		marshalled, err = proto.Marshal(x.UpdateChatRsaKeyNotification)
	case *messages.IncomingNotification_SendMessageNotification:
		marshalled, err = proto.Marshal(x.SendMessageNotification)
	case *messages.IncomingNotification_SendFileNotification:
		marshalled, err = proto.Marshal(x.SendFileNotification)
	default:
		return status.Errorf(codes.Internal, "unknown notification type")
	}
	if err != nil {
		return err
	}

	if err != nil {
		return status.Errorf(codes.Internal, "failed to marshal notification for signing: %v", err)
	}

	signature, err := crypto_utils.SignMessage(privateKey, marshalled)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to sign notification: %v", err)
	}

	// Set the signature in the notification
	notification.EcdsaSignature = signature

	// Send the notification with the signature
	return stream.Send(notification)
}
