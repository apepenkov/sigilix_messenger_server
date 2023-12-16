package grpc_server

import (
	"context"
	"github.com/apepenkov/sigilix_messenger_server/proto/users"
	"github.com/apepenkov/sigilix_messenger_server/server_impl"
	"github.com/golang/protobuf/proto"
)

type userService struct {
	serv *server_impl.ServerImpl
	users.UnimplementedUserServiceServer
}

func (s *userService) Login(ctx context.Context, loginRequest *users.LoginRequest) (*users.LoginResponse, error) {
	dataBytes, _ := proto.Marshal(loginRequest)
	res, err := s.serv.Login(ctx, dataBytes, loginRequest.ClientEcdsaPublicKey, loginRequest.ClientRsaPublicKey)
	if err != nil {
		return nil, err.ToProtoError()
	}
	return res.ToProtobuf().(*users.LoginResponse), nil
}

func (s *userService) SetUsernameConfig(ctx context.Context, setUsernameConfigRequest *users.SetUsernameConfigRequest) (*users.SetUsernameConfigResponse, error) {
	res, err := s.serv.SetUsernameConfig(ctx, setUsernameConfigRequest.Username, setUsernameConfigRequest.SearchByUsernameAllowed)
	if err != nil {
		return nil, err.ToProtoError()
	}
	return res.ToProtobuf().(*users.SetUsernameConfigResponse), nil
}

func (s *userService) SearchByUsername(ctx context.Context, searchByUsernameRequest *users.SearchByUsernameRequest) (*users.SearchByUsernameResponse, error) {
	res, err := s.serv.SearchByUsername(ctx, searchByUsernameRequest.Username)
	if err != nil {
		return nil, err.ToProtoError()
	}
	return res.ToProtobuf().(*users.SearchByUsernameResponse), nil
}
