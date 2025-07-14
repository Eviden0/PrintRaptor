package config

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v3"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

/*
单例模式
*/
var (
	rawYamlData map[string]interface{}
	once        sync.Once
)

func Load() {
	// 读取根目录下的config配置文件
	data, err := os.ReadFile("config.yaml")
	if err != nil {
		log.Fatalf("读取配置文件发生错误,%v", err)
	}
	err = yaml.Unmarshal(data, &rawYamlData)
	if err != nil {
		log.Fatalf("解析配置文件失败: %v", err)
	}
	log.Println("配置文件加载成功,初始化完成...")
}
func getData(key string) (interface{}, error) {
	if rawYamlData == nil {
		return nil, errors.New("配置尚未提前加载,请确保config.yaml 文件被正确加载")
	}
	val, ok := rawYamlData[key]
	if !ok {
		return nil, errors.New("调用了不存在的配置项 <" + key + "> 检查config.yaml文件的写法")
	}
	return val, nil
}

/**
 * GetProxy 拿到socks代理或者http代理
 * 同时封装超时时间
 */
func GetProxy() (*http.Transport, error) {
	var transport *http.Transport
	raw, err := getData("TimeOut")
	if err != nil {
		return nil, err
	}
	duration, ok := raw.(int)
	if !ok {
		duration = 5 //赋默认值
	}
	//log.Println("成功加载超时时间:", duration, "秒")
	timeout := time.Duration(duration) * time.Second
	raw, err = getData("Proxy")
	if err != nil {
		return nil, err
	}
	rawP := raw.(string)
	switch rawP[0] {
	case 'h', 'H':
		//http or https
		parseUrl, err := url.Parse(rawP)
		if err != nil {
			return nil, fmt.Errorf("invalid HTTP proxy address: %v", err)
		}
		transport = &http.Transport{
			Proxy:                 http.ProxyURL(parseUrl),
			DisableKeepAlives:     true,
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // 👈 跳过证书验证
			},
		}
	case 's', 'S':
		dialer, err := proxy.SOCKS5("tcp", rawP, nil, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("failed to create SOCKS5 dialer: %v", err)

		}
		// 转为 net.DialContext
		dialContext := func(network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		}
		transport = &http.Transport{
			Dial:                  dialContext,
			DisableKeepAlives:     true,
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // 👈 跳过证书验证
			},
		}
	default:
		return nil, fmt.Errorf("unsupported proxy type: %s", rawP)
	}
	return transport, nil
}

// GetHeaders
// 支持带cookie或者一些自定义头进行探测,或者存在一些校验失败的情况会露出鸡脚?先写上这个需求
func GetHeaders() (http.Header, error) {
	raw, err := getData("ReqHeader")
	if err != nil {
		return nil, err
	}
	httpHeaders := http.Header{}
	if headers, ok := raw.([]interface{}); ok {
		for _, header := range headers {
			if hmap, ok := header.(map[string]interface{}); ok {
				for k, v := range hmap {
					httpHeaders.Set(k, v.(string)) //TODO:是一个冒险的做法,后面再封装一个有err的断言
				}
			}
		}
	}
	return httpHeaders, nil
}

// GetPostData 默认base64编码,传解码后的data
func GetPostData() (data []byte, err error) {
	raw, err := getData("POST")
	if err != nil {
		return nil, err
	}
	decodeData, err := base64.StdEncoding.DecodeString(raw.(string))
	if err != nil {
		return nil, errors.New("base 解码失败")
	}
	return decodeData, nil
}

func GetTargetFilePath() (string, error) {
	raw, err := getData("TargetFilePath")
	if err != nil {
		return "", err
	}
	filePath, ok := raw.(string)
	if !ok {
		return "", errors.New("TargetFile配置项必须是字符串类型")
	}
	if filePath == "" {
		return "", errors.New("TargetFile配置项不能为空")
	}
	return filePath, nil

}
func GetFingerFilePath() (string, error) {
	raw, err := getData("FingerFilePath")
	if err != nil {
		return "", err
	}
	filePath, ok := raw.(string)
	if !ok {
		return "", errors.New("FingerFilePath配置项必须是字符串类型")
	}
	if filePath == "" {
		return "", errors.New("FingerFilePath配置项不能为空")
	}
	return filePath, nil
}
func IsFastMode() bool {
	raw, err := getData("FastMode")
	if err != nil {
		log.Println("FastMode配置项不存在,请检查config.yaml文件的写法,默认开启快速模式")
		return true //默认是快速模式
	}
	fastMode, ok := raw.(bool)
	if !ok {
		log.Println("FastMode配置项不是布尔类型,请检查config.yaml文件的写法,默认开启快速模式")
		return true
	}
	log.Println("根据config配置文件加载,您已指定精准模式!")
	return fastMode
}
