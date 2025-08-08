package scan

import (
	"PrintRaptor/config"
	"PrintRaptor/fingerprints"
	"PrintRaptor/models"
	"fmt"
	"log"
)

func Scan() {
	//==================初始化==============
	savaType, _ := config.GetSaveMode()
	if config.IsFastMode() {
		//快速模式
		fingerFilePath, err := config.GetFingerFilePath()
		if err != nil {
			log.Fatalf("初始化指纹文件路径失败: %v", err)
		}
		rules, err := fingerprints.LoadRulesFromFile(fingerFilePath)
		fmt.Printf("Loading rules from %s ,Loaded %d 条\n", fingerFilePath, len(rules))
		if err != nil {
			log.Fatal(err)
		}
		targetFilePath, err := config.GetTargetFilePath()
		if err != nil {
			log.Fatalf("初始化目标文件失败: %v", err)
		}
		targetsU, err := models.LoadFromFile(targetFilePath)
		if err != nil {
			log.Fatalf("Failed to load targets from file: %v", err)
		}
		//过一遍responseData即可,若第一次就为空那么直接退出
		for _, targetUrl := range targetsU {
			// 对于每个targetUrl只需要Request一次,然后更换banner.CompiledRule 就去匹配即可
			target, err := NewTarget(targetUrl, &rules[0])
			if err != nil {
				log.Printf("Error creating target for %s: %v", targetUrl, err)
				continue
			}
			banner, err := target.Request()
			if err != nil || banner == nil {
				continue
			}
			for _, rule := range rules {
				banner.CompiledRule = &rule
				// 扫描返回结果
				if banner.Match() {
					result := &models.Result{
						Banner:   banner,
						SaveType: savaType,
					}
					saver := result.GetSaver()
					if err := saver.Save(); err != nil {
						log.Printf("Failed to save result: %v", err)
					}
				}
			}
		}
	} else {
		fingerFilePath, err := config.GetFingerFilePath()
		if err != nil {
			log.Fatalf("初始化指纹文件路径失败: %v", err)
		}
		rules, err := fingerprints.LoadRulesFromFile(fingerFilePath)
		fmt.Printf("🔍 Loading rules from %s ,Loaded %d 条\n", fingerFilePath, len(rules))
		if err != nil {
			log.Fatal(err)
		}
		targetFilePath, err := config.GetTargetFilePath()
		if err != nil {
			log.Fatalf("初始化目标文件失败: %v", err)
		}
		targetsU, err := models.LoadFromFile(targetFilePath)
		if err != nil {
			log.Fatalf("Failed to load targets from file: %v", err)
		}
		concurrent(targetsU, rules, savaType)
		//扫描结束然后写入结果即可
		//抽离出来封装一个函数
		//for _, targetUrl := range targetsU {
		//	for _, rule := range rules {
		//		target, err := NewTarget(targetUrl, &rule)
		//		if err != nil {
		//			log.Printf("Error creating target for %s with rule %s: %v", targetUrl, rule.Name, err)
		//			continue
		//		}
		//		banner, err := target.Request() //发送http请求
		//		banner.Match()
		//	}
		//}
	}
}
