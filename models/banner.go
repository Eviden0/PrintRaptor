package models

import (
	"PrintRaptor/fingerprints"
	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
	"io"
	"os"
	"sync"
)

var logger *logrus.Logger
var once sync.Once

func Init() {
	once.Do(func() {
		logResult := &lumberjack.Logger{
			Filename: "logrus.log",
			MaxSize:  1,
		}
		logger = logrus.New()
		logger.SetFormatter(&logrus.JSONFormatter{})
		logger.SetLevel(logrus.InfoLevel)
		logger.SetOutput(io.MultiWriter(os.Stdout, logResult))
	})
} //初始化logrus

func EndLogger() {
	if logger != nil {
		if lo, ok := logger.Out.(io.Closer); ok {
			lo.Close()
		}
	}
}

type Banner struct {
	ResponseData *fingerprints.ResponseData //包含header,body,hash,用于指纹匹配
	CompiledRule *fingerprints.CompiledRule //加载的指纹识别规则
}

func (banner *Banner) Print() {
	if banner != nil && banner.CompiledRule.AST.Eval(banner.ResponseData) {
		/*
			fmt.Println("命中: " + banner.CompiledRule.Name + "\n标签: " + banner.CompiledRule.Tag + "\n命中规则: " + banner.CompiledRule.Expression)
			fmt.Println("详细信息: ")
			fmt.Println("主机信息: " + banner.ResponseData.Host)
			fmt.Println("标题信息: " + banner.ResponseData.Title)
			fmt.Println("数据包长度:", banner.ResponseData.BodyLength)
			fmt.Println("Icon Hash: " + banner.ResponseData.Hash)
		*/
		logger.WithFields(logrus.Fields{
			"主机信息":      banner.ResponseData.Host,
			"命中":        banner.CompiledRule.Name,
			"标签":        banner.CompiledRule.Tag,
			"命中规则":      banner.CompiledRule.Expression,
			"标题信息":      banner.ResponseData.Title,
			"数据包长度":     banner.ResponseData.BodyLength,
			"Icon Hash": banner.ResponseData.Hash,
		}).Info("success")

	} else {
		//if banner.ResponseData.Body == "" {
		//	fmt.Println(banner.ResponseData.Host + "未能获取到任何信息,请检查网站是否可访问")
		//}
		//fmt.Println(banner.ResponseData.Host + "未匹配到指纹规则" + banner.CompiledRule.Name)
	}
}
