package main

import (
	"context"
	"log"

	"github.com/valkey-io/valkey-go"
)

func NewValkeyClient() (valkey.Client, error) {
	client, err := valkey.NewClient(valkey.ClientOption{
		InitAddress: []string{"127.0.0.1:6379"},
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	err = client.Do(ctx, client.B().Ping().Build()).Error()
	if err != nil {
		return nil, err
	}

	log.Println("Connected to Valkey successfully")
	return client, nil
}
