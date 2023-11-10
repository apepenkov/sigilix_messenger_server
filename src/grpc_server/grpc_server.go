package grpc_server

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"github.com/apepenkov/sigilix_messenger_server/crypto_utils"
	"github.com/apepenkov/sigilix_messenger_server/proto/messages"
	"github.com/apepenkov/sigilix_messenger_server/proto/users"
	"github.com/apepenkov/sigilix_messenger_server/storage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"net"
	"strconv"
)

type contextKey int

const userContextKey contextKey = iota

func IncomingInterceptorSignatureValidator(stor storage.Storage) grpc.UnaryServerInterceptor {

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Errorf(codes.Unauthenticated, "metadata was not provided")
		}
		signatureBase64, ok := md["signature_base64"]
		if !ok || len(signatureBase64) != 1 {
			return nil, status.Errorf(codes.Unauthenticated, "signature was not provided or is invalid")
		}

		// check type of request. if it's a login request, we don't need to validate anything
		if info.FullMethod == "/users.UserService/Login" {
			return handler(ctx, req)
		}

		// check if user_id is provided
		userIdStr, ok := md["user_id"]
		if !ok || len(userIdStr) != 1 {
			return nil, status.Errorf(codes.Unauthenticated, "user_id was not provided or is invalid")
		}
		userId, err := strconv.ParseUint(userIdStr[0], 10, 64)
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "user_id is invalid")
		}

		userData, err := stor.GetUserById(userId)
		if err != nil {
			return nil, status.Errorf(codes.NotFound, "user does not exist")
		}

		ctx = context.WithValue(ctx, userContextKey, userId)

		p, ok := req.(proto.Message)
		if !ok {
			return nil, status.Errorf(codes.Internal, "request does not implement proto.Message interface")
		}
		dataBytes, err := proto.Marshal(p)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to marshal request: %v", err)
		}

		isSigValid, err := crypto_utils.ValidateECDSASignatureFromBase64(userData.EcdsaPublicKeyBytes, dataBytes, signatureBase64[0])

		if err != nil || !isSigValid {
			return nil, status.Errorf(codes.Unauthenticated, "signature is invalid")
		}

		return handler(ctx, req)
	}
}

type GRpcServer struct {
	creds           *credentials.TransportCredentials
	rpcServ         *grpc.Server
	storage         storage.Storage
	ecdsaPrivateKey *ecdsa.PrivateKey
}

func NewGrpcServer(tls *tls.Certificate, storage storage.Storage, ecdsaPrivateKey *ecdsa.PrivateKey) *GRpcServer {
	creds := credentials.NewServerTLSFromCert(tls)
	server := grpc.NewServer(
		grpc.Creds(creds),
		grpc.UnaryInterceptor(IncomingInterceptorSignatureValidator(storage)),
	)

	usersServer := &userService{
		storage:              storage,
		serverECDSAPublicKey: crypto_utils.PublicECDSAKeyToBytes(&ecdsaPrivateKey.PublicKey),
	}
	messagesServer := &messagesService{
		storage:              storage,
		serverECDSAPublicKey: crypto_utils.PublicECDSAKeyToBytes(&ecdsaPrivateKey.PublicKey),
	}

	users.RegisterUserServiceServer(server, usersServer)
	messages.RegisterMessageServiceServer(server, messagesServer)

	srv := GRpcServer{
		creds:           &creds,
		rpcServ:         server,
		storage:         storage,
		ecdsaPrivateKey: ecdsaPrivateKey,
	}
	return &srv
}

func (g *GRpcServer) ListenAndServe(addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return g.rpcServ.Serve(lis)
}
