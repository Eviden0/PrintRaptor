package main

import (
	"PrintRaptor/config"
	"PrintRaptor/fingerprints"
	"PrintRaptor/http"
	"PrintRaptor/models"
	"fmt"
	"log"
)

func main() {
	logo := `  ____  ____  ___ _   _ _____ ____     _    ____ _____ ___  ____   
 |  _ \|  _ \|_ _| \ | |_   _|  _ \   / \  |  _ |_   _/ _ \|  _ \  
 | |_) | |_) || ||  \| | | | | |_) | / _ \ | |_) || || | | | |_) | 
 |  __/|  _ < | || |\  | | | |  _ < / ___ \|  __/ | || |_| |  _ <  
 |_|   |_| \_|___|_| \_| |_| |_| \_/_/   \_|_|    |_| \___/|_| \_\ 

                                          𝓑𝓨 : 𝓔𝓿𝓲𝓭𝓮𝓷`
	fmt.Println(logo)
	config.Load()
	if config.IsFastMode() {
		//快速模式
		fingerFilePath, err := config.GetFingerFilePath()
		if err != nil {
			models.LogLoad.Fatalf("初始化指纹文件路径失败: %v", err)
		}
		rules, err := fingerprints.LoadRulesFromFile(fingerFilePath)
		log.Printf("Loading rules from %s ,Loaded %d 条\n", fingerFilePath, len(rules))
		if err != nil {
			models.LogLoad.Warn(err)
		}
		targetFilePath, err := config.GetTargetFilePath()
		if err != nil {
			models.LogLoad.Fatalf("初始化目标文件失败: %v", err)
		}
		targetsU, err := models.LoadFromFile(targetFilePath)
		if err != nil {
			models.LogLoad.Fatalf("Failed to load targets from file: %v", err)
		}
		//过一遍responseData即可,若第一次就为空那么直接退出
		for _, targetUrl := range targetsU {
			// 对于每个targetUrl只需要Request一次,然后更换banner.CompiledRule 就去匹配即可
			target, err := http.NewTarget(targetUrl, &rules[0])
			if err != nil {
				models.LogLoad.Warn("Error creating target for %s: %v", targetUrl, err)
				continue
			}
			banner, err := target.Request()
			if err != nil || banner == nil {
				models.LogLoad.Warn("Request failed for %s: %v", targetUrl, err)
				continue
			}
			for _, rule := range rules {
				banner.CompiledRule = &rule
				// 这里可以做匹配或打印
				banner.Print()
			}
		}
	} else {
		fingerFilePath, err := config.GetFingerFilePath()
		if err != nil {
			models.LogLoad.Fatalf("初始化指纹文件路径失败: %v", err)
		}
		rules, err := fingerprints.LoadRulesFromFile(fingerFilePath)
		log.Printf("🔍 Loading rules from %s ,Loaded %d 条\n", fingerFilePath, len(rules))
		if err != nil {
			models.LogLoad.Fatal(err)
		}
		targetFilePath, err := config.GetTargetFilePath()
		if err != nil {
			models.LogLoad.Fatalf("初始化目标文件失败: %v", err)
		}
		targetsU, err := models.LoadFromFile(targetFilePath)
		if err != nil {
			models.LogLoad.Fatalf("Failed to load targets from file: %v", err)
		}
		for _, targetUrl := range targetsU {
			for _, rule := range rules {
				target, err := http.NewTarget(targetUrl, &rule)
				if err != nil {
					models.LogLoad.Warn("Error creating target for %s with rule %s: %v", targetUrl, rule.Name, err)
					continue
				}
				banner, err := target.Request()
				banner.Print()
			}
		}
	}
}

