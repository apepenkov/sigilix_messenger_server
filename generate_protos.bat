@echo off

rmdir /s /q "src/proto"
mkdir "src/proto"
mkdir "src/proto/messages"
protoc -I=protobufs/ --go_out=src/proto/messages --go_opt=paths=source_relative --go-grpc_out=src/proto/messages --go-grpc_opt=paths=source_relative protobufs/messages.proto
mkdir "src/proto/users"
protoc -I=protobufs/ --go_out=src/proto/users --go_opt=paths=source_relative --go-grpc_out=src/proto/users --go-grpc_opt=paths=source_relative protobufs/users.proto
