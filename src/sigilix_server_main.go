package main

import (
	"crypto/tls"
	"flag"
	"github.com/apepenkov/sigilix_messenger_server/crypto_utils"
	"github.com/apepenkov/sigilix_messenger_server/grpc_server"
	"github.com/apepenkov/sigilix_messenger_server/logger"
	"github.com/apepenkov/sigilix_messenger_server/storage"
	"github.com/apepenkov/sigilix_messenger_server/storage/memory_storage"
)

func main() {
	var listenAddr, certpath, keypath, base64ecdsakey, storageToUse string
	var generateEcdsaKey, autoRestart bool
	flag.StringVar(&listenAddr, "listen", "localhost:8080", "address to listen on")
	flag.StringVar(&certpath, "cert", "", "path to -cert.pem file")
	flag.StringVar(&keypath, "key", "", "path to -key.pem file")
	flag.StringVar(&base64ecdsakey, "ecdsakey", "", "base64-encoded ECDSA private key")
	flag.StringVar(&storageToUse, "storage", "memory", "storage to use: memory or sqlite")
	flag.BoolVar(&generateEcdsaKey, "generatekey", false, "generate ECDSA key and print it to stdout")
	flag.BoolVar(&autoRestart, "autorestart", false, "automatically restart server on panic")

	flag.Parse()

	log := logger.NewLogger(
		"sigilix_server",
		logger.WithColor(),
		logger.WithPrintCaller(20),
		logger.WithPrintLevel(),
		logger.WithPrintNameTree(20),
		logger.WithPrintTime("2006-01-02 15:04:05.000"),
		logger.WithVerboseLevel(logger.VerboseLevelInfo),
	)

	if generateEcdsaKey {
		key, err := crypto_utils.GenerateKey()
		if err != nil {
			log.Fatalf("failed to generate key: %v\n", err)
		}
		log.Infof("Generated key: %s\n", crypto_utils.PrivateKeyToBytesBase64(key))
		return
	}
	if base64ecdsakey == "" {
		log.Fatalf("ecdsa key must be provided\n")
	}

	ecdsaPrivateKey, err := crypto_utils.PrivateKeyFromBytesBase64(base64ecdsakey)
	if err != nil {
		log.Fatalf("failed to parse ECDSA key: %v\n", err)
	}
	//log.Infof("Parsed ECDSA key. Private: %s\n", crypto_utils.PrivateKeyToBytesBase64(ecdsaPrivateKey))
	log.Infof("Parsed ECDSA key. Public: %s\n", crypto_utils.BytesToBase64(crypto_utils.PublicECDSAKeyToBytes(&ecdsaPrivateKey.PublicKey)))

	if certpath == "" || keypath == "" {
		log.Fatalf("both -cert and -key must be provided\n")
	}

	// load cert
	var tlsCert tls.Certificate

	tlsCert, err = tls.LoadX509KeyPair(certpath, keypath)
	if err != nil {
		log.Fatalf("failed to load cert: %v\n", err)
	}

	var stor storage.Storage

	switch storageToUse {
	case "memory":
		stor = memory_storage.NewInMemoryStorage()
	default:
		log.Fatalf("unknown storage: %s\n", storageToUse)
	}

	srv := grpc_server.NewGrpcServer(
		&tlsCert,
		stor,
		ecdsaPrivateKey,
		log,
	)

	if autoRestart {
		for {
			err = srv.ListenAndServe(listenAddr)
			if err != nil {
				log.Errorf("server failed: %v\n", err)
			}
		}
	} else {
		err = srv.ListenAndServe(listenAddr)
		if err != nil {
			log.Fatalf("server failed: %v\n", err)
		}
	}
}
