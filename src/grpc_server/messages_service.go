package grpc_server

import (
	"github.com/apepenkov/sigilix_messenger_server/proto/messages"
	"github.com/apepenkov/sigilix_messenger_server/storage"
)

type messagesService struct {
	storage              storage.Storage
	serverECDSAPublicKey []byte
	messages.UnimplementedMessageServiceServer
}
