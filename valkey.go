package main

import (
	"context"
	"log"
	"os"

	"github.com/valkey-io/valkey-go"
)

func NewValkeyClient() (valkey.Client, error) {
	valkeyAddress := os.Getenv("VALKEY_ADDRESS")
	if valkeyAddress == "" {
		valkeyAddress = "127.0.0.1:6379"
	}

	client, err := valkey.NewClient(valkey.ClientOption{
		InitAddress: []string{valkeyAddress},
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	err = client.Do(ctx, client.B().Ping().Build()).Error()
	if err != nil {
		return nil, err
	}

	log.Printf("Connected to Valkey successfully at %s", valkeyAddress)
	return client, nil
}
