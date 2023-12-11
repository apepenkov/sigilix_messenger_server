package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/apepenkov/sigilix_messenger_server/crypto_utils"
	"github.com/apepenkov/sigilix_messenger_server/grpc_server"
	"github.com/apepenkov/sigilix_messenger_server/logger"
	"github.com/apepenkov/sigilix_messenger_server/storage"
	"github.com/apepenkov/sigilix_messenger_server/storage/memory_storage"
	"github.com/apepenkov/sigilix_messenger_server/storage/sqlite_storage"
	"math/big"
)

func main() {
	var listenAddr, certpath, keypath, base64ecdsakey, storageToUse, sqliteStoragePath string
	var generateEcdsaKey, autoRestart bool
	flag.StringVar(&listenAddr, "listen", "localhost:8080", "address to listen on")
	flag.StringVar(&certpath, "cert", "", "path to -cert.pem file")
	flag.StringVar(&keypath, "key", "", "path to -key.pem file")
	flag.StringVar(&base64ecdsakey, "ecdsakey", "", "base64-encoded ECDSA private key")
	flag.StringVar(&storageToUse, "storage", "memory", "storage to use: memory or sqlite")
	flag.StringVar(&sqliteStoragePath, "sqlitepath", "sigilix.db", "path to sqlite database")
	flag.BoolVar(&generateEcdsaKey, "generatekey", false, "generate ECDSA key and print it to stdout")
	flag.BoolVar(&autoRestart, "autorestart", false, "automatically restart server on panic")

	flag.Parse()

	log := logger.NewLogger(
		"sigilix_server",
		logger.WithColor(),
		logger.WithPrintCaller(30),
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
	var tlsCert *tls.Certificate

	if certpath == "" || keypath == "" {
		tlsCert = nil
	} else {
		tlsCert_, err := tls.LoadX509KeyPair(certpath, keypath)
		if err != nil {
			log.Fatalf("failed to load cert: %v\n", err)
		}
		tlsCert = &tlsCert_
	}
	// load cert

	var stor storage.Storage

	switch storageToUse {
	case "memory":
		stor = memory_storage.NewInMemoryStorage()
	case "sqlite":
		stor, err = sqlite_storage.NewSqliteStorage(sqliteStoragePath)
	default:
		log.Fatalf("unknown storage: %s\n", storageToUse)
	}
	if err != nil {
		log.Fatalf("failed to initialize storage: %v\n", err)
	}

	srv := grpc_server.NewGrpcServer(
		tlsCert,
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
func main2() {
	key, err := crypto_utils.GenerateKey()
	if err != nil {
		panic(err)
	}
	key.X, _ = big.NewInt(0).SetString("14581313189730622294751604965037280390928378765255123256068340371166498622098", 10)
	key.Y, _ = big.NewInt(0).SetString("44595002123700500999069408116836750861660070657724097605924825364891295807889", 10)
	key.D, _ = big.NewInt(0).SetString("24499662964065618945919505709802698962025494410790255344908628695817224130315", 10)

	data := []byte("elena каширова лох")
	fmt.Printf("PVT X: %s\n", key.X.String())
	fmt.Printf("PVT Y: %s\n", key.Y.String())
	fmt.Printf("PVT D: %s\n", key.D.String())
	pubKeyBytes := crypto_utils.PublicECDSAKeyToBytes(&key.PublicKey)
	pubKeyBase64 := crypto_utils.BytesToBase64(pubKeyBytes)
	fmt.Printf("Public key: %s\n", pubKeyBase64)
	sig, err := crypto_utils.SignMessageBase64(key, data)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Signature: %s\n", sig)
	valid, err := crypto_utils.ValidateECDSASignatureFromBase64(pubKeyBytes, data, sig)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Signature: %v\n", valid)
}
