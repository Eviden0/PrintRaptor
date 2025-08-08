package config

import (
	"fmt"
	"log"
	"testing"
)

func TestConfig(t *testing.T) {
	Load("F:\\Code\\Golang\\Hacking\\PrintRaptor\\config.yaml")
	headers, err := GetMongoUri()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(headers)
}
