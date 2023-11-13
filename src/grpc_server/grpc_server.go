package grpc_server

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"github.com/apepenkov/sigilix_messenger_server/crypto_utils"
	"github.com/apepenkov/sigilix_messenger_server/logger"
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

func smallRandomCode() string {
	buf := make([]byte, 4)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

type contextKey int

const (
	contextKeyUser contextKey = iota
	contextKeyId
	contextKeySignature
)

func interceptor(srv *GRpcServer) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		reqId := smallRandomCode()
		ctx = context.WithValue(ctx, contextKeyId, reqId)

		srv.logger.Infof("[%s] incoming request: %s\n", reqId, info.FullMethod)
		md, ok := metadata.FromIncomingContext(ctx)

		if !ok {
			srv.logger.Errorf("[%s] metadata was not provided\n", reqId)
			return nil, status.Errorf(codes.Unauthenticated, "metadata was not provided")
		}
		signatureBase64, ok := md["signature_base64"]
		if !ok || len(signatureBase64) != 1 {
			srv.logger.Errorf("[%s] signature was not provided\n", reqId)
			return nil, status.Errorf(codes.Unauthenticated, "signature was not provided or is invalid")
		}
		ctx = context.WithValue(ctx, contextKeySignature, signatureBase64[0])

		// check type of request. if it's a login request, we don't need to validate anything
		if info.FullMethod == "/users.UserService/Login" {
			srv.logger.Infof("[%s] login request, skipping signature validation\n", reqId)
		} else {
			// check if user_id is provided
			userIdStr, ok := md["user_id"]
			if !ok || len(userIdStr) != 1 {
				srv.logger.Errorf("[%s] user_id was not provided\n", reqId)
				return nil, status.Errorf(codes.Unauthenticated, "user_id was not provided or is invalid")
			}
			userId, err := strconv.ParseUint(userIdStr[0], 10, 64)
			if err != nil {
				srv.logger.Errorf("[%s] user_id is invalid: %s\n", reqId, userIdStr[0])
				return nil, status.Errorf(codes.Unauthenticated, "user_id is invalid")
			}

			userData, err := srv.storage.GetUserById(userId)
			if err != nil {
				srv.logger.Errorf("[%s] failed to get user: %v\n", reqId, err)
				return nil, status.Errorf(codes.NotFound, "user does not exist")
			}

			ctx = context.WithValue(ctx, contextKeyUser, userId)

			p, ok := req.(proto.Message)
			if !ok {
				srv.logger.Errorf("[%s] request does not implement proto.Message interface\n", reqId)
				return nil, status.Errorf(codes.Internal, "request does not implement proto.Message interface")
			}
			dataBytes, err := proto.Marshal(p)
			if err != nil {
				srv.logger.Errorf("[%s] failed to marshal request: %v\n", reqId, err)
				return nil, status.Errorf(codes.Internal, "failed to marshal request: %v", err)
			}

			isSigValid, err := crypto_utils.ValidateECDSASignatureFromBase64(userData.EcdsaPublicKeyBytes, dataBytes, signatureBase64[0])

			if err != nil || !isSigValid {
				srv.logger.Errorf("[%s] failed to validate signature: %v %v\n", reqId, err, isSigValid)
				return nil, status.Errorf(codes.Unauthenticated, "signature is invalid")
			}

			srv.logger.Infof("[%s] signature is valid, processing request\n", reqId)
		}

		resp, err := handler(ctx, req)

		if err != nil {
			return nil, err
		}
		srv.logger.Infof("[%s] signing response\n", reqId)
		p, ok := resp.(proto.Message)
		if !ok {
			srv.logger.Errorf("[%s] response does not implement proto.Message interface\n", reqId)
			return nil, status.Errorf(codes.Internal, "response does not implement proto.Message interface")
		}

		// Marshal the ProtoBuf message to bytes
		data, err := proto.Marshal(p)
		if err != nil {
			srv.logger.Errorf("[%s] failed to marshal response: %v\n", reqId, err)
			return nil, status.Errorf(codes.Internal, "failed to marshal response: %v", err)
		}

		signature, err := crypto_utils.SignMessageBase64(srv.ecdsaPrivateKey, data)

		if err != nil {
			srv.logger.Errorf("[%s] failed to sign response: %v\n", reqId, err)
			return nil, status.Errorf(codes.Internal, "failed to sign response: %v", err)
		}

		// set "serv_signature_base64" header
		md = metadata.New(map[string]string{
			"serv_signature_base64": signature,
		})
		if err = grpc.SetHeader(ctx, md); err != nil {
			srv.logger.Errorf("[%s] failed to send metadata: %v\n", reqId, err)
			return nil, status.Errorf(codes.Internal, "failed to send metadata: %v", err)
		}

		srv.logger.Infof("[%s] response signed %s\n", reqId, signature)

		return resp, err
	}
}

type GRpcServer struct {
	creds           credentials.TransportCredentials
	rpcServ         *grpc.Server
	storage         storage.Storage
	ecdsaPrivateKey *ecdsa.PrivateKey
	logger          *logger.Logger
}

func NewGrpcServer(tls *tls.Certificate, storage storage.Storage, ecdsaPrivateKey *ecdsa.PrivateKey, log *logger.Logger) *GRpcServer {
	var creds credentials.TransportCredentials = nil
	if tls != nil {
		creds = credentials.NewServerTLSFromCert(tls)
	}
	srv := &GRpcServer{
		creds:           creds,
		rpcServ:         nil,
		storage:         storage,
		ecdsaPrivateKey: ecdsaPrivateKey,
		logger:          log,
	}
	var server *grpc.Server
	if creds == nil {
		server = grpc.NewServer(
			grpc.UnaryInterceptor(interceptor(srv)),
		)
		log.Warningln("running without TLS")
	} else {
		server = grpc.NewServer(
			grpc.Creds(creds),
			grpc.UnaryInterceptor(interceptor(srv)),
		)
	}
	srv.rpcServ = server

	usersServer := &userService{
		storage:              storage,
		serverECDSAPublicKey: crypto_utils.PublicECDSAKeyToBytes(&ecdsaPrivateKey.PublicKey),
		logger:               log.AddChild("users"),
	}
	messagesServer := &messagesService{
		storage:               storage,
		serverECDSAPublicKey:  crypto_utils.PublicECDSAKeyToBytes(&ecdsaPrivateKey.PublicKey),
		serverECDSAPrivateKey: ecdsaPrivateKey,
		logger:                log.AddChild("messages"),
	}

	users.RegisterUserServiceServer(server, usersServer)
	messages.RegisterMessageServiceServer(server, messagesServer)

	return srv
}

func (g *GRpcServer) ListenAndServe(addr string) error {
	g.logger.Infof("starting gRPC server on %s\n", addr)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return g.rpcServ.Serve(lis)
}
