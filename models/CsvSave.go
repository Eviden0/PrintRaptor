package models

import (
	"encoding/csv"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

/*
Host string # 主机名
Title    # 标题
BodyLength # 数据包的长度
Hash # 网站的iconHash
Expression # 命中的指纹表达式,后续一键联动fofa测绘资产
*/
var (
	csvWriter *csv.Writer
	csvFile   *os.File
	once      sync.Once
	csvMutex  sync.Mutex
)

func initCsvWriter() {
	outDir := "out"
	err := os.MkdirAll(outDir, os.ModePerm)
	if err != nil {
		panic(err)
	}
	fileName := time.Now().Format("20060102_150405") + ".csv"
	filePath := filepath.Join(outDir, fileName)
	csvFile, err = os.Create(filePath)
	if err != nil {
		panic(err)
	}
	// 写入 UTF-8 BOM，确保 Excel 正确识别编码
	csvFile.Write([]byte{0xEF, 0xBB, 0xBF})
	csvWriter = csv.NewWriter(csvFile)
	// 写入表头
	csvWriter.Write([]string{"Host", "Title", "Hash", "ICP", "BodyLength", "Expression", "RuleName", "Rank"})
}

type CsvSave struct {
	Banner *Banner
}

func (c *CsvSave) Save() error {
	once.Do(initCsvWriter)
	csvMutex.Lock()
	defer csvMutex.Unlock()
	// 写入数据
	csvWriter.Write([]string{
		c.Banner.ResponseData.Host,
		c.Banner.ResponseData.Title,
		c.Banner.ResponseData.Hash,
		c.Banner.ResponseData.ICP,
		strconv.Itoa(c.Banner.ResponseData.BodyLength),
		c.Banner.CompiledRule.Expression,
		c.Banner.CompiledRule.Name,
		strconv.Itoa(c.Banner.CompiledRule.Rank),
	})
	csvWriter.Flush()
	log.Printf("Csv 成功写入数据: %s", c.Banner.ResponseData.Host)
	return csvWriter.Error()
}

// 程序退出时关闭文件
func CloseCsvFile() {
	if csvFile != nil {
		csvFile.Close()
	}
}
