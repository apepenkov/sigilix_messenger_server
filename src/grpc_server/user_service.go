package grpc_server

import (
	"bytes"
	"context"
	"github.com/apepenkov/sigilix_messenger_server/crypto_utils"
	"github.com/apepenkov/sigilix_messenger_server/logger"
	"github.com/apepenkov/sigilix_messenger_server/proto/users"
	"github.com/apepenkov/sigilix_messenger_server/storage"
	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"strconv"
)

type userService struct {
	storage              storage.Storage
	serverECDSAPublicKey []byte
	logger               *logger.Logger
	users.UnimplementedUserServiceServer
}

func (s *userService) Login(ctx context.Context, loginRequest *users.LoginRequest) (*users.LoginResponse, error) {
	signatureBase64 := ctx.Value(contextKeySignature).(string)
	reqId := ctx.Value(contextKeyId).(string)
	s.logger.Infof("[%s] login request for key %s\n", reqId, crypto_utils.BytesToBase64(loginRequest.ClientEcdsaPublicKey))

	dataBytes, _ := proto.Marshal(loginRequest)

	// we need to validate the signature within the request ONLY in this function.
	// later it will be validated in the interceptor
	isSigValid, err := crypto_utils.ValidateECDSASignatureFromBase64(loginRequest.ClientEcdsaPublicKey, dataBytes, signatureBase64)

	if err != nil {
		s.logger.Errorf("[%s] failed to validate signature: %v\n", reqId, err)
		return nil, status.Errorf(codes.Internal, "failed to validate signature: %v", err)
	}

	if !isSigValid {
		s.logger.Errorf("[%s] signature is invalid\n", reqId)
		return nil, status.Errorf(codes.Unauthenticated, "signature is invalid")
	}

	u, err := s.storage.FetchOrCreateUser(loginRequest.ClientEcdsaPublicKey, loginRequest.ClientRsaPublicKey)
	if err != nil {
		s.logger.Errorf("[%s] failed to fetch or create user: %v\n", reqId, err)
		return nil, status.Errorf(codes.Internal, "failed to fetch or create user: %v", err)
	}
	md := metadata.New(map[string]string{
		"user_id": strconv.FormatUint(u.UserId, 10),
		// Client MUST extract that value and pass it as a header in all requests
	})
	if err = grpc.SetHeader(ctx, md); err != nil {
		s.logger.Errorf("[%s] failed to send metadata: %v\n", reqId, err)
		return nil, status.Errorf(codes.Internal, "failed to send metadata: %v", err)
	}

	if bytes.Compare(u.InitialRsaKeyBytes, loginRequest.ClientRsaPublicKey) != 0 {
		return nil, status.Errorf(codes.PermissionDenied, "RSA key mismatch")
	}

	s.logger.Infof("[%s] login successful for user %d\n", reqId, u.UserId)
	return &users.LoginResponse{
		PrivateInfo:          u.ToPrivateInfo(),
		UserId:               u.UserId,
		ServerEcdsaPublicKey: s.serverECDSAPublicKey,
	}, nil
}

func (s *userService) SetUsernameConfig(ctx context.Context, setUsernameConfigRequest *users.SetUsernameConfigRequest) (*users.SetUsernameConfigResponse, error) {
	userId := ctx.Value(contextKeyUser).(uint64)
	reqId := ctx.Value(contextKeyId).(string)
	var err error

	if setUsernameConfigRequest.Username != "" {
		same, err := s.storage.SearchForUserByUsername(setUsernameConfigRequest.Username)
		if err != nil {
			s.logger.Errorf("[%s] failed to search for user by username: %v\n", reqId, err)
			return nil, status.Errorf(codes.Internal, "failed to search for user by username: %v", err)
		}

		if same != nil && same.UserId != userId {
			s.logger.Errorf("[%s] username %s is already taken\n", reqId, setUsernameConfigRequest.Username)
			return nil, status.Errorf(codes.AlreadyExists, "username %s is already taken", setUsernameConfigRequest.Username)
		}
	}

	err = s.storage.SetUsernameConfig(
		userId,
		setUsernameConfigRequest.Username,
		setUsernameConfigRequest.SearchByUsernameAllowed,
	)
	if err != nil {
		s.logger.Errorf("[%s] failed to set username config: %v\n", reqId, err)
		return nil, status.Errorf(codes.Internal, "failed to set username config: %v", err)
	}
	return &users.SetUsernameConfigResponse{Success: true}, nil
}

func (s *userService) SearchByUsername(ctx context.Context, searchByUsernameRequest *users.SearchByUsernameRequest) (*users.SearchByUsernameResponse, error) {
	found, err := s.storage.SearchForUserByUsername(searchByUsernameRequest.Username)
	reqId := ctx.Value(contextKeyId).(string)

	if err != nil {
		s.logger.Errorf("[%s] failed to search for user by username: %v\n", reqId, err)
		return nil, status.Errorf(codes.Internal, "failed to search for user by username: %v", err)
	}
	if found == nil {
		return &users.SearchByUsernameResponse{}, nil
	} else {
		return &users.SearchByUsernameResponse{
			PublicInfo: found.ToPublicInfo(),
		}, nil
	}
}
