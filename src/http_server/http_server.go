package http_server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"github.com/apepenkov/sigilix_messenger_server/crypto_utils"
	"github.com/apepenkov/sigilix_messenger_server/custom_types"
	"github.com/apepenkov/sigilix_messenger_server/logger"
	"github.com/apepenkov/sigilix_messenger_server/server_impl"
	"io"
	"net/http"
	"strconv"
)

func smallRandomCode() string {
	buf := make([]byte, 4)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

type Serv struct {
	serv       *server_impl.ServerImpl
	Logger     *logger.Logger
	HttpServer *http.Server
	ServerMux  *http.ServeMux
}

func (s *Serv) Middleware(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// set content type to json
		w.Header().Set("Content-Type", "application/json")
		s.Logger.Infof("Incoming request: [%-4s] %s, headers: %v\n", r.Method, r.URL.Path, r.Header)
		mbClose := func() {
			if r.Body != nil {
				_ = r.Body.Close()
			}
		}

		if r.Method != "POST" {
			s.Logger.Errorf("Method is not POST: %s\n", r.Method)
			e := &server_impl.Error{Code: server_impl.ErrInternal, Message: "method is not POST"}
			e.WriteToHttp(w)
			mbClose()
			return
		}

		defer func() {
			if p := recover(); p != nil {
				e := &server_impl.Error{Code: server_impl.ErrInternal, Message: "internal server error"}
				e.WriteToHttp(w)
				mbClose()
				s.Logger.Errorf("Recovered from panic: %v, url: %s\n", p, r.URL.Path)
			}
		}()
		reqId := smallRandomCode()
		r = r.WithContext(context.WithValue(r.Context(), server_impl.ContextKeyReqId, reqId))

		shouldNotPrint := false

		path := r.URL.Path
		if path == "/api/messages/get_notifications" {
			shouldNotPrint = true
		}

		if !shouldNotPrint {
			s.Logger.Infof("[%s] incoming request: %s\n", reqId, path)
		}
		signatureBase64 := r.Header.Get("X-Sigilix-Signature")
		if signatureBase64 == "" {
			s.Logger.Errorf("[%s] signature was not provided\n", reqId)
			e := &server_impl.Error{Code: server_impl.ErrUnauthenticated, Message: "signature was not provided or is invalid"}
			e.WriteToHttp(w)
			mbClose()
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), server_impl.ContextKeySignature, signatureBase64))

		if path == "/api/users/login" {
			s.Logger.Infof("[%s] login request, skipping signature validation\n", reqId)
		} else {
			userIdStr := r.Header.Get("X-Sigilix-User-Id")
			if userIdStr == "" {
				s.Logger.Errorf("[%s] user_id was not provided\n", reqId)
				e := &server_impl.Error{Code: server_impl.ErrUnauthenticated, Message: "user_id was not provided or is invalid"}
				e.WriteToHttp(w)
				mbClose()
				return
			}

			userId, err := strconv.ParseUint(userIdStr, 10, 64)
			if err != nil {
				s.Logger.Errorf("[%s] failed to parse user_id: %v\n", reqId, err)
				e := &server_impl.Error{Code: server_impl.ErrUnauthenticated, Message: "user_id was not provided or is invalid"}
				e.WriteToHttp(w)
				mbClose()
				return
			}

			userData, err := s.serv.Storage.GetUserById(userId)
			if err != nil {
				s.Logger.Errorf("[%s] failed to get user: %v\n", reqId, err)
				e := &server_impl.Error{Code: server_impl.ErrUnauthenticated, Message: "user does not exist"}
				e.WriteToHttp(w)
				mbClose()
				return
			}

			r = r.WithContext(context.WithValue(r.Context(), server_impl.ContextKeyUser, userData.UserId))

			dataBytes := []byte{}
			// read body
			if r.Body != nil {
				dataBytes, err = io.ReadAll(r.Body)
				_ = r.Body.Close()
				if err != nil {
					s.Logger.Errorf("[%s] failed to read body: %v\n", reqId, err)
					e := &server_impl.Error{Code: server_impl.ErrInternal, Message: "failed to read body"}
					e.WriteToHttp(w)
					return
				}
			} else {
				s.Logger.Errorf("[%s] body is empty\n", reqId)
				e := &server_impl.Error{Code: server_impl.ErrInternal, Message: "body is empty"}
				e.WriteToHttp(w)
				return
			}
			// write it back :)
			r.Body = io.NopCloser(bytes.NewBuffer(dataBytes))

			isSigValid, err := crypto_utils.ValidateECDSASignatureFromBase64(userData.EcdsaPublicKeyBytes, dataBytes, signatureBase64)

			if err != nil || !isSigValid {
				s.Logger.Errorf("[%s] failed to validate signature: %v %v\n", reqId, err, isSigValid)
				e := &server_impl.Error{Code: server_impl.ErrUnauthenticated, Message: "signature is invalid"}
				e.WriteToHttp(w)
				mbClose()
				return
			}

			if !shouldNotPrint {
				s.Logger.Infof("[%s] signature is valid, processing request\n", reqId)
			}
		}

		next.ServeHTTP(w, r)

		mbClose()
	})
}

func (s *Serv) Login(w http.ResponseWriter, r *http.Request) {
	reqId := r.Context().Value(server_impl.ContextKeyReqId).(string)
	s.Logger.Infof("[%s] login request\n", reqId)

	dataBytes, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		s.Logger.Errorf("[%s] failed to read body: %v\n", reqId, err)
		e := &server_impl.Error{Code: server_impl.ErrInternal, Message: "failed to read body"}
		e.WriteToHttp(w)
		return
	}

	var reqData *custom_types.LoginRequest

	err = json.Unmarshal(dataBytes, &reqData)

	if err != nil {
		s.Logger.Errorf("[%s] failed to unmarshal request: %v\n", reqId, err)
		e := &server_impl.Error{Code: server_impl.ErrInternal, Message: "failed to unmarshal request"}
		e.WriteToHttp(w)
		return
	}

	if reqData.ClientRsaPublicKey == nil || reqData.ClientEcdaPublicKey == nil || len(reqData.ClientRsaPublicKey) == 0 || len(reqData.ClientEcdaPublicKey) == 0 {
		s.Logger.Errorf("[%s] client rsa or ecdsa public key is empty\n", reqId)
		e := &server_impl.Error{Code: server_impl.ErrInternal, Message: "client rsa or ecdsa public key is empty"}
		e.WriteToHttp(w)
		return
	}

	res, e := s.serv.Login(r.Context(), dataBytes, reqData.ClientEcdaPublicKey, reqData.ClientRsaPublicKey)

	if e != nil {
		s.Logger.Errorf("[%s] failed to login: %s\n", reqId, e.Error())
		e.WriteToHttp(w)
		return
	}

	resBytes, err := json.Marshal(res)
	if err != nil {
		s.Logger.Errorf("[%s] failed to marshal response: %v\n", reqId, err)
		e := &server_impl.Error{Code: server_impl.ErrInternal, Message: "failed to marshal response"}
		e.WriteToHttp(w)
		return
	}

	_, _ = w.Write(resBytes)
}

func (s *Serv) SetUsernameConfig(w http.ResponseWriter, r *http.Request) {
	reqId := r.Context().Value(server_impl.ContextKeyReqId).(string)
	s.Logger.Infof("[%s] set username config request\n", reqId)

	dataBytes, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		s.Logger.Errorf("[%s] failed to read body: %v\n", reqId, err)
		e := &server_impl.Error{Code: server_impl.ErrInternal, Message: "failed to read body"}
		e.WriteToHttp(w)
		return
	}

	var reqData *custom_types.SetUsernameConfigRequest

	err = json.Unmarshal(dataBytes, &reqData)

	if err != nil {
		s.Logger.Errorf("[%s] failed to unmarshal request: %v\n", reqId, err)
		e := &server_impl.Error{Code: server_impl.ErrInternal, Message: "failed to unmarshal request"}
		e.WriteToHttp(w)
		return
	}

	res, e := s.serv.SetUsernameConfig(r.Context(), reqData.Username, reqData.SearchByUsernameAllowed)

	if e != nil {
		s.Logger.Errorf("[%s] failed to set username config: %s\n", reqId, e.Error())
		e.WriteToHttp(w)
		return
	}

	resBytes, err := json.Marshal(res)
	if err != nil {
		s.Logger.Errorf("[%s] failed to marshal response: %v\n", reqId, err)
		e := &server_impl.Error{Code: server_impl.ErrInternal, Message: "failed to marshal response"}
		e.WriteToHttp(w)
		return
	}

	_, _ = w.Write(resBytes)
}

func (s *Serv) SearchByUsername(w http.ResponseWriter, r *http.Request) {
	reqId := r.Context().Value(server_impl.ContextKeyReqId).(string)
	s.Logger.Infof("[%s] search by username request\n", reqId)

	dataBytes, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		s.Logger.Errorf("[%s] failed to read body: %v\n", reqId, err)
		e := &server_impl.Error{Code: server_impl.ErrInternal, Message: "failed to read body"}
		e.WriteToHttp(w)
		return
	}

	var reqData *custom_types.SearchByUsernameRequest

	err = json.Unmarshal(dataBytes, &reqData)

	if err != nil {
		s.Logger.Errorf("[%s] failed to unmarshal request: %v\n", reqId, err)
		e := &server_impl.Error{Code: server_impl.ErrInternal, Message: "failed to unmarshal request"}
		e.WriteToHttp(w)
		return
	}

	res, e := s.serv.SearchByUsername(r.Context(), reqData.Username)

	if e != nil {
		s.Logger.Errorf("[%s] failed to search by username: %s\n", reqId, e.Error())
		e.WriteToHttp(w)
		return
	}

	resBytes, err := json.Marshal(res)
	if err != nil {
		s.Logger.Errorf("[%s] failed to marshal response: %v\n", reqId, err)
		e := &server_impl.Error{Code: server_impl.ErrInternal, Message: "failed to marshal response"}
		e.WriteToHttp(w)
		return
	}

	_, _ = w.Write(resBytes)
}

func (s *Serv) InitChatFromInitializer(w http.ResponseWriter, r *http.Request) {
	reqId := r.Context().Value(server_impl.ContextKeyReqId).(string)
	s.Logger.Infof("[%s] init chat from initializer request\n", reqId)

	dataBytes, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		s.Logger.Errorf("[%s] failed to read body: %v\n", reqId, err)
		e := &server_impl.Error{Code: server_impl.ErrInternal, Message: "failed to read body"}
		e.WriteToHttp(w)
		return
	}

	var reqData *custom_types.InitChatFromInitializerRequest

	err = json.Unmarshal(dataBytes, &reqData)

	if err != nil {
		s.Logger.Errorf("[%s] failed to unmarshal request: %v\n", reqId, err)
		e := &server_impl.Error{Code: server_impl.ErrInternal, Message: "failed to unmarshal request"}
		e.WriteToHttp(w)
		return
	}

	res, e := s.serv.InitChatFromInitializer(r.Context(), reqData.TargetUserId)

	if e != nil {
		s.Logger.Errorf("[%s] failed to init chat from initializer: %s\n", reqId, e.Error())
		e.WriteToHttp(w)
		return
	}

	resBytes, err := json.Marshal(res)
	if err != nil {
		s.Logger.Errorf("[%s] failed to marshal response: %v\n", reqId, err)
		e := &server_impl.Error{Code: server_impl.ErrInternal, Message: "failed to marshal response"}
		e.WriteToHttp(w)
		return
	}

	_, _ = w.Write(resBytes)
}

func (s *Serv) InitChatFromReceiver(w http.ResponseWriter, r *http.Request) {
	reqId := r.Context().Value(server_impl.ContextKeyReqId).(string)
	s.Logger.Infof("[%s] init chat from receiver request\n", reqId)

	dataBytes, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		s.Logger.Errorf("[%s] failed to read body: %v\n", reqId, err)
		e := &server_impl.Error{Code: server_impl.ErrInternal, Message: "failed to read body"}
		e.WriteToHttp(w)
		return
	}

	var reqData *custom_types.InitChatFromReceiverRequest

	err = json.Unmarshal(dataBytes, &reqData)

	if err != nil {
		s.Logger.Errorf("[%s] failed to unmarshal request: %v\n", reqId, err)
		e := &server_impl.Error{Code: server_impl.ErrInternal, Message: "failed to unmarshal request"}
		e.WriteToHttp(w)
		return
	}

	res, e := s.serv.InitChatFromReceiver(r.Context(), reqData.ChatId)

	if e != nil {
		s.Logger.Errorf("[%s] failed to init chat from receiver: %s\n", reqId, e.Error())
		e.WriteToHttp(w)
		return
	}

	resBytes, err := json.Marshal(res)
	if err != nil {
		s.Logger.Errorf("[%s] failed to marshal response: %v\n", reqId, err)
		e := &server_impl.Error{Code: server_impl.ErrInternal, Message: "failed to marshal response"}
		e.WriteToHttp(w)
		return
	}

	_, _ = w.Write(resBytes)
}

func (s *Serv) UpdateChatRsaKey(w http.ResponseWriter, r *http.Request) {
	reqId := r.Context().Value(server_impl.ContextKeyReqId).(string)
	s.Logger.Infof("[%s] update chat rsa key request\n", reqId)

	dataBytes, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		s.Logger.Errorf("[%s] failed to read body: %v\n", reqId, err)
		e := &server_impl.Error{Code: server_impl.ErrInternal, Message: "failed to read body"}
		e.WriteToHttp(w)
		return
	}

	var reqData *custom_types.UpdateChatRsaKeyRequest

	err = json.Unmarshal(dataBytes, &reqData)

	if err != nil {
		s.Logger.Errorf("[%s] failed to unmarshal request: %v\n", reqId, err)
		e := &server_impl.Error{Code: server_impl.ErrInternal, Message: "failed to unmarshal request"}
		e.WriteToHttp(w)
		return
	}

	res, e := s.serv.UpdateChatRsaKey(r.Context(), reqData.ChatId, reqData.RsaPublicKey)

	if e != nil {
		s.Logger.Errorf("[%s] failed to update chat rsa key: %s\n", reqId, e.Error())
		e.WriteToHttp(w)
		return
	}

	resBytes, err := json.Marshal(res)
	if err != nil {
		s.Logger.Errorf("[%s] failed to marshal response: %v\n", reqId, err)
		e := &server_impl.Error{Code: server_impl.ErrInternal, Message: "failed to marshal response"}
		e.WriteToHttp(w)
		return
	}

	_, _ = w.Write(resBytes)
}

func (s *Serv) SendMessage(w http.ResponseWriter, r *http.Request) {
	reqId := r.Context().Value(server_impl.ContextKeyReqId).(string)
	s.Logger.Infof("[%s] send message request\n", reqId)

	dataBytes, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		s.Logger.Errorf("[%s] failed to read body: %v\n", reqId, err)
		e := &server_impl.Error{Code: server_impl.ErrInternal, Message: "failed to read body"}
		e.WriteToHttp(w)
		return
	}

	var reqData *custom_types.SendMessageRequest

	err = json.Unmarshal(dataBytes, &reqData)

	if err != nil {
		s.Logger.Errorf("[%s] failed to unmarshal request: %v\n", reqId, err)
		e := &server_impl.Error{Code: server_impl.ErrInternal, Message: "failed to unmarshal request"}
		e.WriteToHttp(w)
		return
	}

	res, e := s.serv.SendMessage(r.Context(), reqData.ChatId, reqData.EncryptedMessage, reqData.MessageEcdsaSignature)

	if e != nil {
		s.Logger.Errorf("[%s] failed to send message: %s\n", reqId, e.Error())
		e.WriteToHttp(w)
		return
	}

	resBytes, err := json.Marshal(res)
	if err != nil {
		s.Logger.Errorf("[%s] failed to marshal response: %v\n", reqId, err)
		e := &server_impl.Error{Code: server_impl.ErrInternal, Message: "failed to marshal response"}
		e.WriteToHttp(w)
		return
	}

	_, _ = w.Write(resBytes)
}

func (s *Serv) SendFile(w http.ResponseWriter, r *http.Request) {
	reqId := r.Context().Value(server_impl.ContextKeyReqId).(string)
	s.Logger.Infof("[%s] send file request\n", reqId)

	dataBytes, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		s.Logger.Errorf("[%s] failed to read body: %v\n", reqId, err)
		e := &server_impl.Error{Code: server_impl.ErrInternal, Message: "failed to read body"}
		e.WriteToHttp(w)
		return
	}

	var reqData *custom_types.SendFileRequest

	err = json.Unmarshal(dataBytes, &reqData)

	if err != nil {
		s.Logger.Errorf("[%s] failed to unmarshal request: %v\n", reqId, err)
		e := &server_impl.Error{Code: server_impl.ErrInternal, Message: "failed to unmarshal request"}
		e.WriteToHttp(w)
		return
	}

	res, e := s.serv.SendFile(r.Context(), reqData.ChatId, reqData.EncryptedFile, reqData.EncryptedMimeType, reqData.FileEcdsaSignature)

	if e != nil {
		s.Logger.Errorf("[%s] failed to send file: %s\n", reqId, e.Error())
		e.WriteToHttp(w)
		return
	}

	resBytes, err := json.Marshal(res)
	if err != nil {
		s.Logger.Errorf("[%s] failed to marshal response: %v\n", reqId, err)
		e := &server_impl.Error{Code: server_impl.ErrInternal, Message: "failed to marshal response"}
		e.WriteToHttp(w)
		return
	}

	_, _ = w.Write(resBytes)
}

func (s *Serv) GetNotifications(w http.ResponseWriter, r *http.Request) {
	reqId := r.Context().Value(server_impl.ContextKeyReqId).(string)
	s.Logger.Infof("[%s] get notifications request\n", reqId)

	dataBytes, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		s.Logger.Errorf("[%s] failed to read body: %v\n", reqId, err)
		e := &server_impl.Error{Code: server_impl.ErrInternal, Message: "failed to read body"}
		e.WriteToHttp(w)
		return
	}

	var reqData *custom_types.GetNotificationsRequest

	err = json.Unmarshal(dataBytes, &reqData)

	if err != nil {
		s.Logger.Errorf("[%s] failed to unmarshal request: %v\n", reqId, err)
		e := &server_impl.Error{Code: server_impl.ErrInternal, Message: "failed to unmarshal request"}
		e.WriteToHttp(w)
		return
	}

	res, e := s.serv.GetNotifications(r.Context(), reqData.Limit)

	if e != nil {
		s.Logger.Errorf("[%s] failed to get notifications: %s\n", reqId, e.Error())
		e.WriteToHttp(w)
		return
	}

	resBytes, err := json.Marshal(res)
	if err != nil {
		s.Logger.Errorf("[%s] failed to marshal response: %v\n", reqId, err)
		e := &server_impl.Error{Code: server_impl.ErrInternal, Message: "failed to marshal response"}
		e.WriteToHttp(w)
		return
	}

	_, _ = w.Write(resBytes)
}

func New(serv *server_impl.ServerImpl, logger *logger.Logger, addr string) *Serv {
	s := &Serv{serv: serv, Logger: logger}

	s.ServerMux = http.NewServeMux()

	s.ServerMux.Handle("/api/users/login", http.HandlerFunc(s.Login))
	s.ServerMux.Handle("/api/users/set_username_config", http.HandlerFunc(s.SetUsernameConfig))
	s.ServerMux.Handle("/api/users/search_by_username", http.HandlerFunc(s.SearchByUsername))

	s.ServerMux.Handle("/api/messages/init_chat_from_initializer", http.HandlerFunc(s.InitChatFromInitializer))
	s.ServerMux.Handle("/api/messages/init_chat_from_receiver", http.HandlerFunc(s.InitChatFromReceiver))
	s.ServerMux.Handle("/api/messages/update_chat_rsa_key", http.HandlerFunc(s.UpdateChatRsaKey))
	s.ServerMux.Handle("/api/messages/send_message", http.HandlerFunc(s.SendMessage))
	s.ServerMux.Handle("/api/messages/send_file", http.HandlerFunc(s.SendFile))
	s.ServerMux.Handle("/api/messages/get_notifications", http.HandlerFunc(s.GetNotifications))

	s.HttpServer = &http.Server{Addr: addr, Handler: s.Middleware(s.ServerMux)}

	return s
}

func (s *Serv) Start() error {
	return s.HttpServer.ListenAndServe()
}
