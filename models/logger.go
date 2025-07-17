package models

import (
	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
	"io"
	"os"
	"sync"
)

/*
单例模式
*/

var (
	logger *logrus.Logger
	once   sync.Once
)

func CreateLog() *logrus.Logger {
	once.Do(func() {
		logResult := &lumberjack.Logger{
			Filename: "logrus.log",
			MaxSize:  1,
		}
		logger = logrus.New()
		logger.SetLevel(logrus.InfoLevel)
		logger.SetFormatter(&logrus.JSONFormatter{})
		logger.SetOutput(io.MultiWriter(os.Stdout, logResult))
	})
	return logger
}

var LogLoad = CreateLog() //创建全局变量
