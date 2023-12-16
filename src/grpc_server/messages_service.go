package grpc_server

import (
	"context"
	"crypto/ecdsa"
	"github.com/apepenkov/sigilix_messenger_server/crypto_utils"
	"github.com/apepenkov/sigilix_messenger_server/proto/messages"
	"github.com/apepenkov/sigilix_messenger_server/server_impl"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"time"
)

type messagesService struct {
	serv *server_impl.ServerImpl
	messages.UnimplementedMessageServiceServer
}

func (ms *messagesService) InitChatFromInitializer(ctx context.Context, initChatFromInitializerRequest *messages.InitChatFromInitializerRequest) (*messages.InitChatFromInitializerResponse, error) {
	res, err := ms.serv.InitChatFromInitializer(ctx, initChatFromInitializerRequest.TargetUserId)
	if err != nil {
		return nil, err.ToProtoError()
	}
	return res.ToProtobuf().(*messages.InitChatFromInitializerResponse), nil
}

func (ms *messagesService) InitChatFromReceiver(ctx context.Context, initChatFromReceiverRequest *messages.InitChatFromReceiverRequest) (*messages.InitChatFromReceiverResponse, error) {
	res, err := ms.serv.InitChatFromReceiver(ctx, initChatFromReceiverRequest.ChatId)
	if err != nil {
		return nil, err.ToProtoError()
	}
	return res.ToProtobuf().(*messages.InitChatFromReceiverResponse), nil
}
func (ms *messagesService) UpdateChatRsaKey(ctx context.Context, updateChatRsaKeyRequest *messages.UpdateChatRsaKeyRequest) (*messages.UpdateChatRsaKeyResponse, error) {
	res, err := ms.serv.UpdateChatRsaKey(ctx, updateChatRsaKeyRequest.ChatId, updateChatRsaKeyRequest.RsaPublicKey)
	if err != nil {
		return nil, err.ToProtoError()
	}
	return res.ToProtobuf().(*messages.UpdateChatRsaKeyResponse), nil
}
func (ms *messagesService) SendMessage(ctx context.Context, sendMessageRequest *messages.SendMessageRequest) (*messages.SendMessageResponse, error) {
	res, err := ms.serv.SendMessage(ctx, sendMessageRequest.ChatId, sendMessageRequest.EncryptedMessage, sendMessageRequest.MessageEcdsaSignature)
	if err != nil {
		return nil, err.ToProtoError()
	}
	return res.ToProtobuf().(*messages.SendMessageResponse), nil
}
func (ms *messagesService) SendFile(ctx context.Context, sendFileRequest *messages.SendFileRequest) (*messages.SendFileResponse, error) {
	res, err := ms.serv.SendFile(ctx, sendFileRequest.ChatId, sendFileRequest.EncryptedFile, sendFileRequest.EncryptedMimeType, sendFileRequest.FileEcdsaSignature)
	if err != nil {
		return nil, err.ToProtoError()
	}
	return res.ToProtobuf().(*messages.SendFileResponse), nil
}
func (ms *messagesService) SubscribeToIncomingNotifications(subReq *messages.SubscriptionRequest, stream messages.MessageService_SubscribeToIncomingNotificationsServer) error {
	ctx := stream.Context()
	userId := ctx.Value(server_impl.ContextKeyUser).(uint64)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			notifications, err := ms.serv.Storage.FetchAndRemoveNotifications(userId, 10)
			if err != nil {
				return status.Errorf(codes.Internal, "failed to fetch notifications: %v", err)
			}
			for _, notification := range notifications {
				if err := signAndSendNotification(stream, notification.ToProtobuf().(*messages.IncomingNotification), ms.serv.ServerECDSAPrivateKey); err != nil {
					return err // This could be a stream.Send error or signing error
				}
			}
		}
	}
}

func (ms *messagesService) GetNotifications(ctx context.Context, getNotificationsRequest *messages.GetNotificationsRequest) (*messages.GetNotificationsResponse, error) {
	res, err := ms.serv.GetNotifications(ctx, getNotificationsRequest.Limit)
	if err != nil {
		return nil, err.ToProtoError()
	}
	return res.ToProtobuf().(*messages.GetNotificationsResponse), nil
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
