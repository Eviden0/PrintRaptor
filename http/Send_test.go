package http

import (
	"PrintRaptor/config"
	"PrintRaptor/fingerprints"
	"fmt"
	"log"
	"testing"
)

func TestSend(t *testing.T) {
	config.Load()
	yamlPath := "F:\\Code\\Golang\\Hacking\\PrintRaptor\\source\\special.yaml"
	fmt.Printf("🔍 Loading rules from %s \n", yamlPath)
	rules, err := fingerprints.LoadRulesFromFile(yamlPath)
	if err != nil {
		log.Fatal(err)
	}
	targetUrl := "http://localhost:8080/"
	for _, rule := range rules {
		target, _ := NewTarget(targetUrl, &rule)
		banner, err := target.Request()
		if err != nil {
			log.Fatal(err)
		}
		result := banner.CompiledRule.AST.Eval(banner.ResponseData)
		if result {
			fmt.Println("命中: " + target.CompiledRule.Name + "\n标签: " + target.CompiledRule.Tag + "\n命中规则: " + target.CompiledRule.Expression)
			fmt.Println("详细信息: ")
			fmt.Println("主机信息: " + banner.ResponseData.Host)
			fmt.Println("标题信息: " + banner.ResponseData.Title)
			fmt.Println("数据包长度:", banner.ResponseData.BodyLength)
			fmt.Println("Icon Hash: " + banner.ResponseData.Hash)
		}
	}
}
