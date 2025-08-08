package models

import (
	"bufio"
	"bytes"
	"net/url"
	"os"
	"strings"
)

/*
初始化目标,可从txt文件中读取目标列表
对于只有host部分的检查
对于纯ip的检查
*/
// addSchemeIfMissing 根据端口或内容自动添加 http/https scheme
func addSchemeIfMissing(line string) string {
	lower := strings.ToLower(line)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return line
	}
	// 判断端口
	if strings.Contains(line, ":443") {
		return "https://" + line
	}
	// 默认使用 http
	return "http://" + line
}
func LoadFromFile(targetPath string) ([]*url.URL, error) {
	targets := make([]*url.URL, 0)
	fileBytes, err := os.ReadFile(targetPath)
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(bytes.NewReader(fileBytes))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		//做解析处理
		//比如只输入host或者ip的
		line = addSchemeIfMissing(line)
		parseUrl, err := url.Parse(line)
		if err != nil {
			return nil, err
		}
		targets = append(targets, parseUrl)
	}
	return targets, nil
}
