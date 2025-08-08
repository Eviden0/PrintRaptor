package test

import (
	"PrintRaptor/config"
	"PrintRaptor/fingerprints"
	"PrintRaptor/models"
	"PrintRaptor/scan"
	"fmt"
	"log"
	"testing"
)

func TestScan(t *testing.T) {
	config.Load()
	yamlPath := "F:\\Code\\Golang\\Hacking\\PrintRaptor\\source\\special.yaml"
	fmt.Printf("🔍 Loading rules from %s \n", yamlPath)
	rules, err := fingerprints.LoadRulesFromFile(yamlPath)
	if err != nil {
		log.Fatal(err)
	}
	targetsU, err := models.LoadFromFile("F:\\Code\\Golang\\Hacking\\PrintRaptor\\source\\IP.txt")
	if err != nil {
		t.Fatalf("Failed to load targets from file: %v", err)
	}
	for _, targetUrl := range targetsU {
		for _, rule := range rules {
			target, err := scan.NewTarget(targetUrl, &rule)
			if err != nil {
				log.Printf("Error creating target for %s with rule %s: %v", targetUrl, rule.Name, err)
				continue
			}
			banner, err := target.Request()
			banner.Print()
		}
	}
}
func TestCommanScan(t *testing.T) {
	config.Load()
	yamlPath := "F:\\Code\\Golang\\Hacking\\PrintRaptor\\source\\finger.yaml"
	fmt.Printf("🔍 Loading rules from %s \n", yamlPath)
	rules, err := fingerprints.LoadRulesFromFile(yamlPath)
	if err != nil {
		log.Fatal(err)
	}
	targetsU, err := models.LoadFromFile("F:\\Code\\Golang\\Hacking\\PrintRaptor\\source\\IP.txt")
	if err != nil {
		t.Fatalf("Failed to load targets from file: %v", err)
	}
	//过一遍responseData即可,若第一次就为空那么直接退出
	for _, targetUrl := range targetsU {
		// 对于每个targetUrl只需要Request一次,然后更换banner.CompiledRule 就去匹配即可
		target, err := scan.NewTarget(targetUrl, &rules[0])
		if err != nil {
			log.Printf("Error creating target for %s: %v", targetUrl, err)
			continue
		}
		banner, err := target.Request()
		if err != nil || banner == nil {
			log.Printf("Request failed for %s: %v", targetUrl, err)
			continue
		}
		for _, rule := range rules {
			banner.CompiledRule = &rule
			// 这里可以做匹配或打印
			banner.Print()
		}
	}
}
