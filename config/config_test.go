package config

import (
	"fmt"
	"log"
	"testing"
)

func TestConfig(t *testing.T) {
	Load()
	headers, err := GetHeaders()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(headers)
}
