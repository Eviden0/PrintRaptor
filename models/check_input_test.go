package models

import (
	"log"
	"net/http"
	"testing"
)

func TestInput(t *testing.T) {
	tt := "www.xtu.edu.cn"
	//url, err := url.Parse(tt)
	//if err != nil {
	//	log.Fatal(err)
	//}
	_, err := http.Get(tt)
	if err != nil {
		log.Fatal(err)
	}
}
