package server_impl

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ErrorCodes int

const (
	ErrCodeUnknown ErrorCodes = iota
	ErrInternal
	ErrUnauthenticated
	ErrPermissionDenied
	AlreadyExists
	ErrNotFound
)

type Error struct {
	Code    ErrorCodes
	Message string
}

//func (e *Error) Error() string {
//	return e.Message
//}

func (e *Error) ToProtoError() error {
	errForProto := codes.Unknown
	switch e.Code {
	case ErrInternal:
		errForProto = codes.Internal
		break
	case ErrUnauthenticated:
		errForProto = codes.Unauthenticated
		break
	case ErrPermissionDenied:
		errForProto = codes.PermissionDenied
		break
	case AlreadyExists:
		errForProto = codes.AlreadyExists
		break
	case ErrNotFound:
		errForProto = codes.NotFound
		break
	default:
		errForProto = codes.Unknown
		break
	}
	return status.Errorf(errForProto, e.Message)
}

func (e *Error) ToHTTPError() int {
	errForHTTP := 500
	switch e.Code {
	case ErrInternal:
		errForHTTP = 500
		break
	case ErrUnauthenticated:
		errForHTTP = 401
		break
	case ErrPermissionDenied:
		errForHTTP = 403
		break
	case AlreadyExists:
		errForHTTP = 409
		break
	case ErrNotFound:
		errForHTTP = 404
		break
	default:
		errForHTTP = 500
		break
	}
	return errForHTTP
}
