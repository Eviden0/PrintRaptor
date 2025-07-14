package models

import (
	"PrintRaptor/fingerprints"
	"fmt"
)

type Banner struct {
	ResponseData *fingerprints.ResponseData //包含header,body,hash,用于指纹匹配
	CompiledRule *fingerprints.CompiledRule //加载的指纹识别规则
}

func (banner *Banner) Print() {
	if banner != nil && banner.CompiledRule.AST.Eval(banner.ResponseData) {
		fmt.Println("命中: " + banner.CompiledRule.Name + "\n标签: " + banner.CompiledRule.Tag + "\n命中规则: " + banner.CompiledRule.Expression)
		fmt.Println("详细信息: ")
		fmt.Println("主机信息: " + banner.ResponseData.Host)
		fmt.Println("标题信息: " + banner.ResponseData.Title)
		fmt.Println("数据包长度:", banner.ResponseData.BodyLength)
		fmt.Println("Icon Hash: " + banner.ResponseData.Hash)
	} else {
		//if banner.ResponseData.Body == "" {
		//	fmt.Println(banner.ResponseData.Host + "未能获取到任何信息,请检查网站是否可访问")
		//}
		//fmt.Println(banner.ResponseData.Host + "未匹配到指纹规则" + banner.CompiledRule.Name)
	}
}
