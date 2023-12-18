package server_impl

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"fmt"
	"github.com/apepenkov/sigilix_messenger_server/crypto_utils"
	"github.com/apepenkov/sigilix_messenger_server/custom_types"
	errors_impl "github.com/apepenkov/sigilix_messenger_server/errors_impl"
	"github.com/apepenkov/sigilix_messenger_server/logger"
	"github.com/apepenkov/sigilix_messenger_server/storage"
)

type contextKey int

const (
	ContextKeyUser contextKey = iota
	ContextKeyReqId
	ContextKeySignature
)

type ServerImpl struct {
	Storage               storage.Storage
	ServerECDSAPublicKey  []byte
	ServerECDSAPrivateKey *ecdsa.PrivateKey
	Logger                *logger.Logger
}

func (s *ServerImpl) Login(ctx context.Context, dataBytes []byte, clientEcdsaPublicKey []byte, clientRsaPublicKey []byte) (*custom_types.LoginResponse, *errors_impl.Error) {
	signatureBase64 := ctx.Value(ContextKeySignature).(string)
	reqId := ctx.Value(ContextKeyReqId).(string)
	s.Logger.Infof("[%s] login request for key %s\n", reqId, crypto_utils.BytesToBase64(clientEcdsaPublicKey))

	// we need to validate the signature within the request ONLY in this function.
	// later it will be validated in the interceptor
	isSigValid, err := crypto_utils.ValidateECDSASignatureFromBase64(clientEcdsaPublicKey, dataBytes, signatureBase64)

	if err != nil {
		s.Logger.Errorf("[%s] failed to validate signature: %v\n", reqId, err)
		//return nil, status.Errorf(codes.Internal, "failed to validate signature: %v", err)
		return nil, &errors_impl.Error{Code: errors_impl.ErrInternal, Message: fmt.Sprintf("failed to validate signature: %v", err)}
	}

	if !isSigValid {
		s.Logger.Errorf("[%s] signature is invalid: sig: %s, data: %x\n", reqId, signatureBase64, dataBytes)
		//return nil, status.Errorf(codes.Unauthenticated, "signature is invalid")
		return nil, &errors_impl.Error{Code: errors_impl.ErrUnauthenticated, Message: "signature is invalid"}
	}

	u, err := s.Storage.FetchOrCreateUser(clientEcdsaPublicKey, clientRsaPublicKey)
	if err != nil {
		s.Logger.Errorf("[%s] failed to fetch or create user: %v\n", reqId, err)
		//return nil, status.Errorf(codes.Internal, "failed to fetch or create user: %v", err)
		return nil, &errors_impl.Error{Code: errors_impl.ErrInternal, Message: fmt.Sprintf("failed to fetch or create user: %v", err)}
	}
	//md := metadata.New(map[string]string{
	//	"user_id": strconv.FormatUint(u.UserId, 10),
	//})
	//if err = grpc.SetHeader(ctx, md); err != nil {
	//	s.Logger.Errorf("[%s] failed to send metadata: %v\n", reqId, err)
	//	//return nil, status.Errorf(codes.Internal, "failed to send metadata: %v", err)
	//	return nil, &errors_impl.Error{errors_impl.ErrInternal, fmt.Sprintf("failed to send metadata: %v", err)}
	//}

	if bytes.Compare(u.InitialRsaKeyBytes, clientRsaPublicKey) != 0 {
		//return nil, status.Errorf(codes.PermissionDenied, "RSA key mismatch")
		return nil, &errors_impl.Error{Code: errors_impl.ErrPermissionDenied, Message: "RSA key mismatch"}
	}

	s.Logger.Infof("[%s] login successful for user %d\n", reqId, u.UserId)
	return &custom_types.LoginResponse{
		PrivateInfo:          u.ToPrivateInfo(),
		UserId:               u.UserId,
		ServerEcdsaPublicKey: s.ServerECDSAPublicKey,
	}, nil
}

func (s *ServerImpl) SetUsernameConfig(ctx context.Context, setUsername string, searchable bool) (*custom_types.SetUsernameConfigResponse, *errors_impl.Error) {
	userId := ctx.Value(ContextKeyUser).(uint64)
	reqId := ctx.Value(ContextKeyReqId).(string)
	var err error

	if setUsername != "" {
		same, err := s.Storage.SearchForUserByUsername(setUsername)
		if err != nil {
			s.Logger.Errorf("[%s] failed to search for user by username: %v\n", reqId, err)
			//return nil, status.Errorf(codes.Internal, "failed to search for user by username: %v", err)
			return nil, &errors_impl.Error{Code: errors_impl.ErrInternal, Message: fmt.Sprintf("failed to search for user by username: %v", err)}
		}

		if same != nil && same.UserId != userId {
			s.Logger.Errorf("[%s] username %s is already taken\n", reqId, setUsername)
			//return nil, status.Errorf(codes.AlreadyExists, "username %s is already taken", setUsername)
			return nil, &errors_impl.Error{Code: errors_impl.AlreadyExists, Message: fmt.Sprintf("username %s is already taken", setUsername)}
		}
	}

	err = s.Storage.SetUsernameConfig(
		userId,
		setUsername,
		searchable,
	)
	if err != nil {
		s.Logger.Errorf("[%s] failed to set username config: %v\n", reqId, err)
		//return nil, status.Errorf(codes.Internal, "failed to set username config: %v", err)
		return nil, &errors_impl.Error{Code: errors_impl.ErrInternal, Message: fmt.Sprintf("failed to set username config: %v", err)}
	}
	return &custom_types.SetUsernameConfigResponse{Success: true}, nil
}

func (s *ServerImpl) SearchByUsername(ctx context.Context, searchUsername string) (*custom_types.SearchByUsernameResponse, *errors_impl.Error) {
	found, err := s.Storage.SearchForUserByUsername(searchUsername)
	reqId := ctx.Value(ContextKeyReqId).(string)

	if err != nil {
		s.Logger.Errorf("[%s] failed to search for user by username: %v\n", reqId, err)
		//return nil, status.Errorf(codes.Internal, "failed to search for user by username: %v", err)
		return nil, &errors_impl.Error{Code: errors_impl.ErrInternal, Message: fmt.Sprintf("failed to search for user by username: %v", err)}
	}
	if found == nil {
		return &custom_types.SearchByUsernameResponse{}, nil
	} else {
		return &custom_types.SearchByUsernameResponse{
			PublicInfo: found.ToPublicInfo(),
		}, nil
	}
}
