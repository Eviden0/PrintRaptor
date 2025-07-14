package models

import (
	"bufio"
	"bytes"
	"net/url"
	"os"
)

/*
初始化目标,可从txt文件中读取目标列表,直接传参一个 path string
也可从命令行参数中读取目标,直接传参一个[]string
*/

func LoadFromFile(targetPath string) ([]*url.URL, error) {
	targets := make([]*url.URL, 0)
	fileBytes, err := os.ReadFile(targetPath)
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(bytes.NewReader(fileBytes))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		parseUrl, err := url.Parse(line)
		if err != nil {
			return nil, err
		}
		targets = append(targets, parseUrl)
	}
	return targets, nil
}
