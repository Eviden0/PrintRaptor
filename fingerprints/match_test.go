package fingerprints

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"
)

/*
并发场景:
在复用一个banner的情况下
加载指纹库所有指纹进行匹配,那么一条条rule为并发变量
*/

type Rule struct {
	Name string         // 规则名称
	Expr *regexp.Regexp // 正则表达式规则
}

func TestMatch(t *testing.T) {
	// 你的原始文本
	rawText := `Welcome to GoLang server. Version: v1.2.3`

	// 假设你有很多规则（这里简单写几个）
	rules := []Rule{
		{"GoLang", regexp.MustCompile(`(?i)golang`)},
		{"Version", regexp.MustCompile(`v\d+\.\d+\.\d+`)},
		{"PHP", regexp.MustCompile(`(?i)php`)},
		{"Apache", regexp.MustCompile(`(?i)apache`)},
	}
	// 用于保存匹配成功的规则名
	var matched []string

	// 使用 WaitGroup 来等待所有 Goroutine 完成
	var wg sync.WaitGroup

	// 使用 Channel 并发收集匹配结果
	resultCh := make(chan string, len(rules))

	// 并发启动每个规则匹配
	for _, rule := range rules {
		wg.Add(1)
		go func(r Rule) {
			defer wg.Done()
			if r.Expr.MatchString(rawText) {
				resultCh <- r.Name
			}
		}(rule)
	}

	// 启动一个 Goroutine 关闭 Channel（避免死锁）
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// 收集所有匹配结果
	for name := range resultCh {
		matched = append(matched, name)
	}
	// 输出匹配成功的规则
	fmt.Println("匹配成功的规则:", strings.Join(matched, ", "))
}
