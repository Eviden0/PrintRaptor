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
	"reflect"
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

func Load(args ...string) {
	// 读取根目录下的config配置文件
	var data []byte
	var err error
	if len(args) == 0 {
		//默认加载位置
		data, err = os.ReadFile("config.yaml")
		if err != nil {
			log.Fatalf("读取配置文件发生错误,%v", err)
		}
	} else {
		data, err = os.ReadFile(args[0])
		if err != nil {
			log.Fatalf("读取配置文件发生错误,%v", err)
		}
	}
	err = yaml.Unmarshal(data, &rawYamlData)
	if err != nil {
		log.Fatalf("解析配置文件失败: %v", err)
	}
	initMongo()
	log.Println("配置文件加载成功,初始化完成...")
}

// ConfigNotFoundError 表示 key 不存在
type ConfigNotFoundError struct {
	Key string
}

func (e *ConfigNotFoundError) Error() string {
	return fmt.Sprintf("配置项 <%s> 不存在,该项是必选项,请填入config.yaml", e.Key)
}

// ConfigTypeMismatchError 表示类型不匹配
type ConfigTypeMismatchError struct {
	Key          string
	ExpectedType string
	ActualType   string
}

func (e *ConfigTypeMismatchError) Error() string {
	return fmt.Sprintf("配置项 <%s> 类型不匹: 期望得到的类型为 <%s>,实际为 <%s>\n", e.Key, e.ExpectedType, e.ActualType)
}

func getData[T any](key string) (T, error) {
	var zero T

	if rawYamlData == nil {
		return zero, errors.New("配置尚未加载，请先调用 Load()")
	}

	val, ok := rawYamlData[key]
	if !ok {
		return zero, &ConfigNotFoundError{Key: key}
	}

	expected := reflect.TypeOf(zero)
	actual := reflect.TypeOf(val)

	// 类型匹配或兼容转换
	switch any(zero).(type) {
	case int:
		switch v := val.(type) {
		case int:
			return any(v).(T), nil
		case float64:
			return any(int(v)).(T), nil
		}
	case float64:
		if v, ok := val.(float64); ok {
			return any(v).(T), nil
		}
	case string:
		if v, ok := val.(string); ok {
			return any(v).(T), nil
		}
	case bool:
		if v, ok := val.(bool); ok {
			return any(v).(T), nil
		}
	case []interface{}:
		if v, ok := val.([]interface{}); ok {
			return any(v).(T), nil
		}
	case map[string]interface{}:
		if v, ok := val.(map[string]interface{}); ok {
			return any(v).(T), nil
		}
	}

	// 最后尝试直接断言
	if casted, ok := val.(T); ok {
		return casted, nil
	}

	return zero, &ConfigTypeMismatchError{
		Key:          key,
		ExpectedType: expected.String(),
		ActualType:   actual.String(),
	}
}

/**
 * GetProxy 拿到socks代理或者http代理
 * 同时封装超时时间
 */
func GetProxy() (*http.Transport, error) {
	var transport *http.Transport
	duration, err := getData[int]("TimeOut")
	if err != nil {
		switch e := err.(type) {
		case *ConfigNotFoundError:
			return nil, e
		case *ConfigTypeMismatchError:
			log.Printf("TimeOut参数 设置类型错误,采用默认值处理: %vs", e)
			duration = 3
		default:
			log.Printf("未知错误,程序错误")
			return nil, err
		}
	}
	//log.Println("成功加载超时时间:", duration, "秒")
	timeout := time.Duration(duration) * time.Second

	rawP, err := getData[string]("Proxy")
	if err != nil {
		//默认不提供Proxy也行
		transport = &http.Transport{
			Proxy:                 nil,
			DisableKeepAlives:     true,
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // 👈 跳过证书验证
			},
		}
		return transport, nil
	}
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
				InsecureSkipVerify: true,
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
				InsecureSkipVerify: true, // 跳过证书验证
			},
		}
	default:
		return nil, fmt.Errorf("unsupported proxy : %s", rawP)
	}
	return transport, nil
}

// GetHeaders
// 支持带cookie或者一些自定义头进行探测,或者存在一些校验失败的情况会露出鸡脚?先写上这个需求
func GetHeaders() (http.Header, error) {
	httpHeaders := http.Header{}
	raw, err := getData[[]interface{}]("ReqHeader")
	if err != nil {
		return httpHeaders, err
	}
	for _, header := range raw {
		if hmap, ok := header.(map[string]interface{}); ok {
			for k, v := range hmap {
				httpHeaders.Set(k, v.(string))
			}
		}
	}
	return httpHeaders, nil
}

// GetPostData 默认base64编码,传解码后的data
func GetPostData() (data []byte, err error) {
	raw, err := getData[string]("POST")
	if err != nil {
		return nil, err
	}
	decodeData, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, errors.New("PostBody base解码失败,请检查是否编码放入config.yaml文件里")
	}
	return decodeData, nil
}

func GetTargetFilePath() (string, error) {
	filePath, err := getData[string]("TargetFilePath")
	if err != nil || filePath == "" {
		return "", err
	}
	return filePath, nil
}

func GetFingerFilePath() (string, error) {
	filePath, err := getData[string]("FingerFilePath")
	if err != nil || filePath == "" {
		return "", err
	}
	return filePath, nil
}

func IsFastMode() bool {
	fastMode, err := getData[bool]("FastMode")
	if err != nil {
		log.Println("FastMode配置项不存在,如需开启精准模式: 请检查config.yaml文件的写法 <===> 默认开启快速模式")
		return true //默认是快速模式
	}
	if !fastMode {
		log.Println("根据config配置文件加载,您已指定精准模式!")
	}
	return fastMode
}

func GetMongoUri() (string, error) {
	Uri, err := getData[string]("MongoUri")
	if err != nil {
		return "", errors.New("未检查到MongoDB数据库的配置文件,若需要开启数据库功能则配置<MongoUri>参数到配置文件")
	}
	return Uri, nil
}
func GetSaveMode() (uint8, error) {
	mode, err := getData[int]("SaveMode")
	if err != nil {
		return 1, nil
	}
	return uint8(mode), nil
}
