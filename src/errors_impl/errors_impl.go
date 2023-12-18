package errors_impl

import (
	"encoding/json"
	"fmt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net/http"
)

type ErrorCodes int

const (
	ErrCodeUnknown ErrorCodes = iota
	ErrInternal
	ErrUnauthenticated
	ErrPermissionDenied
	AlreadyExists
	ErrNotFound
	ErrInvalidRequest
)

type Error struct {
	Code    ErrorCodes
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("Error: %s, code: %v", e.Message, e.Code)
}

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
	case ErrInvalidRequest:
		errForProto = codes.InvalidArgument
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
	case ErrInvalidRequest:
		errForHTTP = 400
	default:
		errForHTTP = 500
		break
	}
	return errForHTTP
}

type ErrorJSON struct {
	Code    ErrorCodes `json:"code"`
	Message string     `json:"message"`
}

func (e *Error) WriteToHttp(w http.ResponseWriter) {
	w.WriteHeader(e.ToHTTPError())
	errJSON := ErrorJSON{
		Code:    e.Code,
		Message: e.Message,
	}
	jsonBytes, _ := json.Marshal(errJSON)
	w.Write(jsonBytes)
}
