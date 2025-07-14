package http

import (
	"PrintRaptor/config"
	"PrintRaptor/fingerprints"
	"PrintRaptor/models"
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/twmb/murmur3"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Target 解析输入信息得到
type Target struct {
	U            *url.URL
	CompiledRule *fingerprints.CompiledRule
}

func NewTarget(targetUrl *url.URL, rule *fingerprints.CompiledRule) (*Target, error) {
	return &Target{
		U:            targetUrl,
		CompiledRule: rule,
	}, nil
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:55.0) Gecko/20100101 Firefox/55.0",
	"Mozilla/5.0 (Windows NT 6.1; rv:55.0) Gecko/20100101 Firefox/55.0",
	"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0",
	"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0",
	"Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0",
	"Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:27.0) Gecko/20121011 Firefox/27.0",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:23.0) Gecko/20130406 Firefox/23.0",
	"Mozilla/5.0 (Windows NT 6.1; rv:22.0) Gecko/20130405 Firefox/22.0",
	"Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:21.0.0) Gecko/20121011 Firefox/21.0.0",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:21.0) Gecko/20130331 Firefox/21.0",
	"Mozilla/5.0 (Windows NT 6.1; rv:21.0) Gecko/20130328 Firefox/21.0",
	"Mozilla/5.0 (Windows NT 5.1; rv:21.0) Gecko/20100101 Firefox/21.0",
	"Mozilla/5.0 (Windows NT 6.1; rv:6.0) Gecko/20100101 Firefox/19.0",
	"Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:16.0.1) Gecko/20121011 Firefox/16.0.1",
	"Mozilla/5.0 (Windows NT 6.2; WOW64; rv:15.0) Gecko/20120910144328 Firefox/15.0.2",
	"Mozilla/5.0 (Windows NT 5.1; rv:14.0) Gecko/20120405 Firefox/14.0a1",
	"Mozilla/5.0 (Windows NT 6.0; rv:14.0) Gecko/20100101 Firefox/14.0.1",
	"Mozilla/5.0 (Windows NT 5.1; rv:12.0) Gecko/20120403211507 Firefox/12.0",
	"Mozilla/5.0 (Windows NT 5.1; rv:11.0) Gecko Firefox/11.0",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:6.0a2) Gecko/20110613 Firefox/6.0a2",
	"Mozilla/5.0 (Windows NT 5.0; WOW64; rv:6.0) Gecko/20100101 Firefox/6.0",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:5.0) Gecko/20110619 Firefox/5.0",
	"Mozilla/5.0 (Windows NT 5.2; WOW64; rv:5.0) Gecko/20100101 Firefox/5.0",
	"Mozilla/5.0 (Windows NT 5.0; rv:5.0) Gecko/20100101 Firefox/5.0",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:2.0b9pre) Gecko/20101228 Firefox/4.0b9pre",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:2.0b8pre) Gecko/20101128 Firefox/4.0b8pre",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:2.0b7) Gecko/20101111 Firefox/4.0b7",
	"Mozilla/5.0 (Windows NT 5.2; rv:2.0b13pre) Gecko/20110304 Firefox/4.0b13pre",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:2.0b11pre) Gecko/20110129 Firefox/4.0b11pre",
	"Mozilla/5.0 (Windows NT 6.1; rv:2.0b10pre) Gecko/20110113 Firefox/4.0b10pre",
	"Mozilla/5.0 (Windows NT 6.1; rv:2.0) Gecko/20110319 Firefox/4.0",
	"Mozilla/5.0 (Windows; Windows NT 5.1; zh-CN;; rv:1.9.2a1pre) Gecko/20090402 Firefox/3.6a1pre",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:42.0) Gecko/20100101 Firefox/42.0",
	"Mozilla/5.0 (Windows NT 5.1; rv:43.0) Gecko/20100101 Firefox/43.0",
	"Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:52.0) Gecko/20100101 Firefox/52.0",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:60.0) Gecko/20100101 Firefox/60.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0",
	"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:31.0) Gecko/20100101 Firefox/31.0",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:43.0) Gecko/20100101 Firefox/43.0",
	"Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0",
	"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:61.0) Gecko/20100101 Firefox/61.0",
	"Mozilla/5.0 (Windows NT 6.1; rv:56.0) Gecko/20100101 Firefox/56.0",
	"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101 Firefox/60.0",
	"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:63.0) Gecko/20100101 Firefox/63.0",
	"Mozilla/5.0 (Windows NT 6.1; rv:59.0) Gecko/20100101 Firefox/59.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:52.0) Gecko/20100101 Firefox/52.0 Cyberfox/52.9.1",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0",
	"Mozilla/5.0 (Windows NT 6.2; WOW64; rv:47.0) Gecko/20100101 Firefox/47.0",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0",
	"Mozilla/5.0 (Windows NT 6.1; rv:40.0) Gecko/20100101 Firefox/40.0",
	"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:61.0) Gecko/20100101 Firefox/61.0",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101 Firefox/60.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:65.0) Gecko/20100101 Firefox/65.0",
	"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:65.0) Gecko/20100101 Firefox/65.0",
	"Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:63.0) Gecko/20100101 Firefox/63.0",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:64.0) Gecko/20100101 Firefox/64.0",
	"Mozilla/5.0 (Windows NT 6.1; rv:64.0) Gecko/20100101 Firefox/64.0",
	"Mozilla/5.0 (Windows NT 6.1; rv:51.0) Gecko/20100101 Firefox/51.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0",
	"Mozilla/5.0 (Windows NT 6.3; rv:60.0) Gecko/20100101 Firefox/60.0",
	"Mozilla/5.0 (Windows NT 5.1; rv:35.0) Gecko/20100101 Firefox/35.0",
	"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:47.0) Gecko/20100101 Firefox/47.0",
	"Mozilla/5.0 (Windows NT 6.1; rv:34.0) Gecko/20100101 Firefox/34.0",
	"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:66.0) Gecko/20100101 Firefox/66.0",
	"Mozilla/5.0 (Windows NT 5.1; rv:36.0) Gecko/20100101 Firefox/36.0",
	"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:34.0) Gecko/20100101 Firefox/34.0",
	"Mozilla/5.0 (Windows NT 6.2; WOW64; rv:65.0) Gecko/20100101 Firefox/65.0",
	"Mozilla/5.0 (Windows NT 6.1; rv:66.0) Gecko/20100101 Firefox/66.0",
	"Mozilla/5.0 (Windows NT 6.1; rv:57.0) Gecko/20100101 Firefox/57.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:60.5) Gecko/20100101 Firefox/60.5",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/62.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 h1atfoAh-17 Firefox/66.0",
	"Mozilla/5.0 (Windows NT 10.0; rv:66.0) Gecko/20100101 Firefox/66.0",
	"Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0",
	"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:67.0) Gecko/20100101 Firefox/67.0",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:67.0) Gecko/20100101 Firefox/67.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:68.0) Gecko/20100101 Firefox/68.0",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0",
	"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0",
	"Mozilla/5.0 (Windows NT 5.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0",
	"Mozilla/5.0 (Windows NT 10.0; rv:67.0) Gecko/20100101 Firefox/67.0",
	"Mozilla/5.0 (Windows NT 5.1; rv:37.0) Gecko/20100101 Firefox/37.0",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0",
	"Mozilla/5.0 (Windows NT 6.2; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
	"Mozilla/5.0 (Windows NT 6.3; rv:56.0) Gecko/20100101 Firefox/56.0",
	"Mozilla/5.0 (Windows NT 5.1; rv:51.0) Gecko/20100101 Firefox/51.0",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:68.0) Gecko/20100101 Firefox/68.0",
	"Mozilla/5.0 (Windows NT 5.1; rv:7.0.1) Gecko/20100101 Firefox/7.0.1",
	"Mozilla/5.0 (Windows NT 5.1; rv:33.0) Gecko/20100101 Firefox/33.0",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.7.12) Gecko/20050915 Firefox/1.0.7",
	"Mozilla/5.0 (Windows NT 6.0; rv:34.0) Gecko/20100101 Firefox/34.0",
	"Mozilla/5.0 (Windows NT 5.1; rv:40.0) Gecko/20100101 Firefox/40.0",
	"Mozilla/5.0 (Windows NT 6.1; rv:17.0) Gecko/20100101 Firefox/20.6.14",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:44.0) Gecko/20100101 Firefox/44.0",
	"Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0",
	"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:63.0) Gecko/20100101 Firefox/63.0",
	"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:51.0) Gecko/20100101 Firefox/51.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:36.0) Gecko/20100101 Firefox/36.0",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:39.0) Gecko/20100101 Firefox/39.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0",
	"Mozilla/5.0 (Windows NT 5.1; rv:32.0) Gecko/20100101 Firefox/32.0",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.7.8) Gecko/20050511 Firefox/1.0.4",
	"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:48.0) Gecko/20100101 Firefox/48.0",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0",
	"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:58.0) Gecko/20100101 Firefox/58.0",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:51.0) Gecko/20100101 Firefox/51.0",
	"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:43.0) Gecko/20100101 Firefox/43.0",
	"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:44.0) Gecko/20100101 Firefox/44.0",
	"Mozilla/5.0 (Windows NT 6.0; rv:16.0) Gecko/20130722 Firefox/16.0",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.9.0.4) Gecko/2008102920 Firefox/3.0.4",
	"Mozilla/5.0 (Windows NT 6.1; rv:53.0) Gecko/20100101 Firefox/53.0",
	"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0",
	"Mozilla/5.0 (Windows NT 6.1; rv:31.0) Gecko/20100101 Firefox/31.0",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.8) Gecko/20051111 Firefox/1.5",
	"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:44.0) Gecko/20100101 Firefox/44.0",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.8.1.7) Gecko/20070914 Firefox/2.0.0.7",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.8.1.14) Gecko/20080404 Firefox/2.0.0.14",
	"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:59.0) Gecko/20100101 Firefox/59.0",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.8.1.11) Gecko/20071127 Firefox/2.0.0.11",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.8.1.3) Gecko/20070309 Firefox/2.0.0.3",
	"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:47.0) Gecko/20100101 Firefox/47.0",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.8.1.12) Gecko/20080201 Firefox/2.0.0.12",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.9.0.1) Gecko/2008070208 Firefox/3.0.1",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:48.0) Gecko/20100101 Firefox/48.0",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:34.0) Gecko/20100101 Firefox/34.0",
	"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.9.0.5) Gecko/2008120122 Firefox/3.0.5",
	"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:73.0) Gecko/20100101 Firefox/73.0",
	"Mozilla/5.0 (Windows NT 10.0; rv:74.0) Gecko/20100101 Firefox/74.0",
	"Mozilla/5.0 (Windows NT 6.3; rv:74.0) Gecko/20100101 Firefox/74.0",
	"Mozilla/5.0 (Windows NT 6.2; rv:60.0) Gecko/20100101 Firefox/60.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:60.8) Gecko/20100101 Firefox/60.8",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 9REByQIi-32 Firefox/74.0",
	"Mozilla/5.0 (Windows NT 10.0; rv:72.0) Gecko/20100101 Firefox/72.0",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:75.0) Gecko/20100101 Firefox/75.0",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0",
	"Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:76.0) Gecko/20100101 Firefox/76.0",
	"Mozilla/5.0 (Windows NT 10.0; rv:73.0) Gecko/20100101 Firefox/73.0",
	"Mozilla/5.0 (Windows NT 6.1; rv:73.0) Gecko/20100101 Firefox/73.0",
	"Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:60.0) Gecko/20100101 Firefox/60.0",
	"Mozilla/5.0 (Windows NT 6.2; rv:74.0) Gecko/20100101 Firefox/74.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:53.0) Gecko/20100101 Firefox/53.0",
	"Mozilla/5.0 (Windows NT 5.2; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0",
	"Mozilla/5.0 (Windows NT 6.3; rv:73.0) Gecko/20100101 Firefox/73.0",
	"Mozilla/5.0 (Windows NT 6.1; rv:76.0) Gecko/20100101 Firefox/76.0",
	"Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:79.0) Gecko/20100101 Firefox/79.0",
	"Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:77.0) Gecko/20100101 Firefox/77.0",
	"Mozilla/5.0 (Windows NT 10.0; rv:79.0) Gecko/20100101 Firefox/79.0",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:77.0) Gecko/20100101 Firefox/77.0",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:76.0) Gecko/20100101 Firefox/76.0",
	"Mozilla/5.0 (Windows NT 6.2; rv:26.0) Gecko/20100101 Firefox/26.0",
	"Mozilla/5.0 (Windows NT 10.0; rv:58.0) Gecko/20100101 Firefox/58.0",
	"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0",
	"Mozilla/5.0 (Windows NT 6.1; rv:80.0) Gecko/20100101 Firefox/80.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:81.0) Gecko/20100101 Firefox/81.0",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0",
	"Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:42.0) Gecko/20100101 Firefox/42.0 Cyberfox/42.0.1",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0",
	"Mozilla/5.0 (Windows NT 10.0; rv:83.0) Gecko/20100101 Firefox/83.0",
	"Mozilla/5.0 (Windows NT 6.3; rv:78.0) Gecko/20100101 Firefox/78.0",
	"Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:85.0) Gecko/20100101 Firefox/85.0",
	"Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0",
	"Mozilla/5.0 (Windows NT 6.1; rv:71.0) Gecko/20100101 Firefox/71.0",
	"Mozilla/5.0 (Windows NT 6.1; rv:82.0) Gecko/20100101 Firefox/82.0",
	"Mozilla/5.0 (Windows NT 6.1; rv:83.0) Gecko/20100101 Firefox/83.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; rv:84.0) Gecko/20100101 Firefox/84.0",
	"Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0",
	"Mozilla/5.0 (Windows NT 6.2; rv:84.0) Gecko/20100101 Firefox/84.0",
	"Mozilla/5.0 (Windows NT 10.0; rv:81.0) Gecko/20100101 Firefox/81.0",
	"Mozilla/5.0 (Windows NT 6.1; rv:85.0) Gecko/20100101 Firefox/85.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0",
	"Mozilla/5.0 (Windows NT 6.1; rv:86.0) Gecko/20100101 Firefox/86.0",
	"Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0",
	"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:58.0) Gecko/20100101 Firefox/58.0",
	"Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:85.0) Gecko/20100101 Firefox/85.0",
	"Mozilla/5.0 (Windows NT 10.0; zh-CN;; rv:1.9.0.20) Gecko/20151226 Firefox/3.6.14",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:45.0) Gecko/20100101 Firefox/45.0 Cyberfox/45.0",
	"Mozilla/5.0 (Windows NT 6.1; rv:87.0) Gecko/20100101 Firefox/87.0",
	"Mozilla/5.0 (Windows NT 6.3; rv:86.0) Gecko/20100101 Firefox/86.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0",
	"Mozilla/5.0 (Windows NT 10.0; rv:86.0) Gecko/20100101 Firefox/86.0",
	"Mozilla/5.0 (Windows NT 6.0; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:49.0) Gecko/20100101 Firefox/49.0",
	"Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.04",
	"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/44.0",
	"Mozilla/5.0 (Windows NT 6.3; rv:72.0) Gecko/20100101 Firefox/72.0",
	"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:86.1) Gecko/20100101 Firefox/86.1",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/50.0",
	"Mozilla/5.0 (Windows NT 6.2; rv:86.0) Gecko/20100101 Firefox/86.0",
	"Mozilla/5.0 (Windows NT 10.0; rv:82.0) Gecko/20100101 Firefox/82.0",
	"Mozilla/5.0 (Windows NT 6.2; rv:85.0) Gecko/20100101 Firefox/85.0",
	"Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:85.0) Gecko/20100101 Firefox/85.0",
	"Mozilla/5.0 (Windows NT 10.1; WOW64; rv:40.0) Gecko/20100101 Firefox/99",
	"Mozilla/5.0 (Windows NT 6.2; WOW64; rv:59.0) Gecko/20100101 Firefox/59.0",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0",
	"Mozilla/5.0 (Windows NT 10.0; rv:87.0) Gecko/20100101 Firefox/87.0",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0",
	"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0",
	"Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0",
	"Mozilla/5.0 (Windows NT 6.3; rv:87.0) Gecko/20100101 Firefox/87.0",
	"Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
	"Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:46.0) Gecko/20100101 Firefox/46.0",
	"Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:52.0) Gecko/20100101 Firefox/52.0 Cyberfox/52.8.0",
	"Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.9.0.5) Gecko/2009011615 Firefox/3.0.5",
	"Mozilla/5.0 (Windows; U; Windows NT 6.1; zh-CN;; rv:1.9.2b5) Gecko/20091204 Firefox/3.6b5",
	"Mozilla/5.0 (Windows; U; Windows NT 6.1;; zh-CN; rv:1.9.2.8) Gecko/20100722 AskTbADAP/3.9.1.14019 Firefox/3.6.8",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.9.2.8) Gecko/20100722 Firefox/3.6.8",
	"Mozilla/5.0 (Windows; U; Windows NT 6.0; zh-CN;; rv:1.9.2.4) Gecko/20100513 Firefox/3.6.4",
	"Mozilla/5.0 (Windows; U; Windows NT 6.1;; zh-CN; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3",
	"Mozilla/5.0 (Windows; U; Windows NT 6.0;; zh-CN; rv:1.9.2.28) Gecko/20120306 Firefox/3.6.28",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1;; zh-CN; rv:1.9.2.20) Gecko/20110803 Firefox/3.6.20",
	"Mozilla/5.0 (Windows; U; Windows NT 6.0; zh-CN;; rv:1.9.2.17) Gecko/20110420 Firefox/3.6.17",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1;; zh-CN; rv:1.9.1.13) Gecko/20100914 Firefox/3.6.16",
	"Mozilla/5.0 (Windows; U; Windows NT 6.1; zh-CN;; rv:1.9.2.14) Gecko/20110218 Firefox/3.6.14",
	"Mozilla/5.0 (Windows; U; Windows NT 5.2;  rv:1.9.2.11) Gecko/20101012 Firefox/3.6.11",
	"Mozilla/5.0 (Windows; U; Windows NT 6.1; zh-CN;; rv:1.9.2.17) Gecko/20110420 Firefox/3.6",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.9.1b4pre) Gecko/20090401 Firefox/3.5b4pre",
	"Mozilla/5.0 (Windows; U; Windows NT 6.1;; zh-CN; rv:1.9.1.9) Gecko/20100315 Firefox/3.5.9",
	"Mozilla/5.0 (Windows; U; Windows NT 6.1;; zh-CN; rv:1.9.1.6) Gecko/20091201 Firefox/3.5.6",
	"Mozilla/5.0 (Windows; U; Windows NT 6.0;; zh-CN; rv:1.9.1.5) Gecko/20091102 MRA 5.5 (build 02842) Firefox/3.5.5",
	"Mozilla/5.0 (Windows; U; Windows NT 5.2; zh-CN;; rv:1.9.1.4) Gecko/20091007 Firefox/3.5.4",
	"Mozilla/5.0 (Windows; U; Windows NT 6.1; zh-CN;; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.9.1.2) Gecko/20090729 Firefox/3.5.2",
	"Mozilla/5.0 (Windows; U; Windows NT 6.1; zh-CN;; rv:1.9.1.16) Gecko/20101130 Firefox/3.5.16 FirePHP/0.4",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1;; zh-CN; rv:1.9.1.12) Gecko/20100824 MRA 5.7 (build 03755) Firefox/3.5.12",
	"Mozilla/5.0 (Windows; U; Windows NT 6.0;; zh-CN; rv:1.9.1.1) Gecko/20090715 Firefox/3.5.1",
	"Mozilla/5.0 (Windows; U; Windows NT 6.1; zh-CN;; rv:1.9.1b3) Gecko/20090305 Firefox/3.1b3",
	"Mozilla/5.0 (Windows; U; Windows NT 6.0; zh-CN;; rv:1.9.1b3) Gecko/20090405 Firefox/3.1b3",
	"Mozilla/5.0 (Windows; U; Windows NT 6.0; x64; zh-CN;; rv:1.9.1b2pre) Gecko/20081026 Firefox/3.1b2pre",
	"Mozilla/5.0 (Windows; U; Windows NT 6.1; zh-CN;; rv:1.9.1b2) Gecko/20081201 Firefox/3.1b2",
	"Mozilla/5.0 (Windows; U; Windows NT 6.0; zh-CN;; rv:1.9.1b2) Gecko/20081201 Firefox/3.1b2",
	"Mozilla/5.0 (Windows; U; Windows NT 6.0; zh-CN;; rv:1.9.1b2) Gecko/20081127 Firefox/3.1b1",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.9b5pre) Gecko/2008030706 Firefox/3.0b5pre",
	"Mozilla/5.0 (Windows; U; Windows NT 5.2;; zh-CN; rv:1.9b5) Gecko/2008032620 Firefox/3.0b5",
	"Mozilla/5.0 (X11; U; Windows NT 5.0; zh-CN;; rv:1.9b4) Gecko/2008030318 Firefox/3.0b4",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1;; zh-CN; rv:1.9b4) Gecko/2008030714 Firefox/3.0b4",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1;; zh-CN; rv:1.9b3) Gecko/2008020514 Firefox/3.0b3",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.9b1) Gecko/2007110703 Firefox/3.0b1",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1;; zh-CN; rv:1.9.0.2pre) Gecko/2008082305 Firefox/3.0.2pre",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.9.1b3pre) Gecko/20090213 Firefox/3.0.1b3pre",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.9a1) Gecko/20100202 Firefox/3.0.18",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1;  ; rv:1.9.0.14) Gecko/2009082707 Firefox/3.0.14",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.9.0.13) Gecko/2009073022 Firefox/3.0.13",
	"Mozilla/5.0 (Windows; U; Windows NT 6.0;; zh-CN; rv:1.9.0.12) Gecko/2009070611 Firefox/3.0.12",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.9.0.1) Gecko/2008070208 Firefox/3.0.0",
	"Mozilla/5.0 (Windows; U; Windows NT 6.0; zh-CN;; rv:1.8.1b2) Gecko/20060821 Firefox/2.0b2",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.8.1b2) Gecko/20060821 Firefox/2.0b2",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.8.1b1) Gecko/20060710 Firefox/2.0b1",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1;; zh-CN; rv:1.8.1b1) Gecko/20060710 Firefox/2.0b1",
	"Mozilla/5.0 (Windows; U; Windows NT 5.0; zh-CN;; rv:1.8.1b1) Gecko/20060710 Firefox/2.0b1",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.8) Gecko/20060319 Firefox/2.0a1",
	"Mozilla/5.0 (Windows; Windows NT 5.1; zh-CN;; rv:1.8.1.9) Gecko/20071025 Firefox/2.0.0.9",
	"Mozilla/5.0 (Windows; U; Windows NT 6.0;; zh-CN; rv:1.8.1.9) Gecko/20071025 Firefox/2.0.0.9",
	"Mozilla/5.0 (Windows; U; Windows NT 5.2;; zh-CN; rv:1.8.1.9) Gecko/20071025 Firefox/2.0.0.9",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1;; zh-CN; rv:1.8.1.9) Gecko/20071025 Firefox/2.0.0.9",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.8.1.17pre) Gecko/20080715 Firefox/2.0.0.8pre",
	"Mozilla/5.0 (Windows; U; Windows NT 6.0; zh-CN;; rv:1.8.1.7) Gecko/20070914 Firefox/2.0.0.7",
	"Mozilla/5.0 (Windows; U; Windows NT 6.0; en_US; rv:1.8.1.6) Gecko/20070725 Firefox/2.0.0.7",
	"Mozilla/5.0 (Windows; U; Windows NT 6.0; zh-CN;; rv:1.8.1.7) Gecko/20070914 Firefox/2.0.0.7",
	"Mozilla/5.0 (Windows; U; Windows NT 5.2;; zh-CN; rv:1.8.1.7) Gecko/20070914 Firefox/2.0.0.7",
	"Mozilla/5.0 (Windows; U; Windows NT 6.0; zh-CN;; rv:1.8.1.5) Gecko/20070713 Firefox/2.0.0.5",
	"Mozilla/5.0 (Windows; U; Windows NT 5.2;; zh-CN; rv:1.8.1.5) Gecko/20070713 Firefox/2.0.0.5",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.8.1.5) Gecko/20070713 Firefox/2.0.0.5",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.8.1.2pre) Gecko/20070118 Firefox/2.0.0.2pre",
	"Mozilla/5.0 (Windows; U; Windows NT 6.1; zh-CN;; rv:1.8.1.20) Gecko/20081217 Firefox/2.0.0.20",
	"Mozilla/5.0 (Windows; U; Windows NT 6.0;; zh-CN; rv:1.8.1.20) Gecko/20081217 Firefox/2.0.0.20",
	"Mozilla/5.0 (Windows; U; Windows NT 5.2; zh-CN;; rv:1.8.1.20) Gecko/20081217 Firefox/2.0.0.20",
	"Mozilla/5.0 (Windows; U; Windows NT 6.0; zh-CN;; rv:1.8.1.20) Gecko/20081217 Firefox/2.0.0.19",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1;; zh-CN; rv:1.8.1.19) Gecko/20081201 Firefox/2.0.0.19",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1;; zh-CN; rv:1.8.1.18) Gecko/20081029 Firefox/2.0.0.18",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.8.1.18) Gecko/20081029 Firefox/2.0.0.18",
	"Mozilla/5.0 (Windows; U; Windows NT 6.0;; zh-CN; rv:1.8.1.17) Gecko/20080829 Firefox/2.0.0.17",
	"Mozilla/5.0 (Windows; U; Windows NT 6.0; zh-CN;; rv:1.8.1.14) Gecko/20080404 Firefox/2.0.0.17",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.8.1.17) Gecko/20080829 Firefox/2.0.0.17",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1;; zh-CN; rv:1.8.1.17) Gecko/20080829 Firefox/2.0.0.17",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.9.0.3) Gecko/2008092417 Firefox/2.0.0.17",
	"Mozilla/5.0 (Windows; U; Windows NT 5.0;; zh-CN; rv:1.8.1.17) Gecko/20080829 Firefox/2.0.0.17",
	"Mozilla/5.0 (Windows; U; WinNT4.0; zh-CN;; rv:1.8.1.16) Gecko/20080702 Firefox/2.0.0.16",
	"Mozilla/5.0 (Windows; U; Windows NT 6.0;; zh-CN; rv:1.8.1.16) Gecko/20080702 Firefox/2.0.0.16",
	"Mozilla/5.0 (Windows; U; Windows NT 6.0; zh-CN;; rv:1.8.1.16) Gecko/20080702 Firefox/2.0.0.16",
	"Mozilla/5.0 (Windows; U; Windows NT 6.0; zh-CN;; rv:1.8.1.15) Gecko/20080623 Firefox/2.0.0.15",
	"Mozilla/5.0 (Windows; U; Windows NT 5.2;; zh-CN; rv:1.8.1.15) Gecko/20080623 Firefox/2.0.0.15",
	"Mozilla/5.0 (Windows; U; Windows NT 5.0; zh-CN;; rv:1.8.1.15) Gecko/20080623 Firefox/2.0.0.15",
	"Mozilla/5.0 (Windows; U; Windows NT 6.0;; zh-CN; rv:1.8.1.13) Gecko/20080311 Firefox/2.0.0.13",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.8.1.13) Gecko/20080311 Firefox/2.0.0.13",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.8.1.13) Gecko/20080311 Firefox/2.0.0.13",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.8.1.11) Gecko/20071127 Firefox/2.0.0.13",
	"Mozilla/5.0 (Windows NT 6.1; U;; zh-CN; rv:1.8.1) Gecko/20061208 Firefox/2.0.0",
	"Mozilla/5.0 (Windows NT 6.0; U;; zh-CN; rv:1.8.1) Gecko/20061208 Firefox/2.0.0",
	"Mozilla/5.0 (Windows; U; Windows NT 5.0; ; rv:1.8.0.7) Gecko/20060917 Firefox/1.9.0.1",
	"Mozilla/5.0 (Windows; U; Windows NT 5.0; ; rv:1.8.0.1) Gecko/20060111 Firefox/1.9.0",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.9a1) Gecko/20060323 Firefox/1.6a1",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.9a1) Gecko/20051220 Firefox/1.6a1",
	"Mozilla/5.0 (Windows; U; Windows NT 6.0; zh-CN;; rv:1.8.0.9) Gecko/20061206 Firefox/1.5.0.9",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.8.0.9) Gecko/20061206 Firefox/1.5.0.9",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.8.0.9) Gecko/20061206 Firefox/1.5.0.9",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1;; zh-CN; rv:1.8.0.9) Gecko/20061206 Firefox/1.5.0.9",
	"Mozilla/5.0 (Windows; U; Windows NT 6.0; zh-CN;; rv:1.8.0.8) Gecko/20061025 Firefox/1.5.0.8",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1;; zh-CN; rv:1.8.0.8) Gecko/20061025 Firefox/1.5.0.8",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.8.0.3) Gecko/20060426 Firefox/1.5.0.3",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1;; zh-CN; rv:1.8.0.3) Gecko/20060426 Firefox/1.5.0.3",
	"Mozilla/5.0 (Windows; U; Win 9x 4.90; zh-CN;; rv:1.8.0.3) Gecko/20060426 Firefox/1.5.0.3",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.8.0.2) Gecko/20060308 Firefox/1.5.0.2",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.8.0.2) Gecko/20060308 Firefox/1.5.0.2",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1;; zh-CN; rv:1.8.0.2) Gecko/20060308 Firefox/1.5.0.2",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.8.0.2) Gecko/20060308 Firefox/1.5.0.2",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.8.0.2) Gecko/20060406 Firefox/1.5.0.2",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.8.0.2) Gecko/20060308 Firefox/1.5.0.2",
	"Mozilla/5.0 (Windows; U; Windows NT 5.2; zh-CN;; rv:1.8.0.12) Gecko/20070508 Firefox/1.5.0.12",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1;; zh-CN; rv:1.8.0.12) Gecko/20070508 Firefox/1.5.0.12",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1;; zh-CN; rv:1.8.0.11) Gecko/20070312 Firefox/1.5.0.11",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1;; zh-CN; rv:1.8.0.11) Gecko/20070312 Firefox/1.5.0.11",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1;; zh-CN; rv:1.8.0.11) Gecko/20070312 Firefox/1.5.0.11",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.8.0.11) Gecko/20070312 Firefox/1.5.0.11",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.8.0.11) Gecko/20070312 Firefox/1.5.0.11",
	"Mozilla/5.0 (Windows; U; Windows NT 5.0;; zh-CN; rv:1.8.0.11) Gecko/20070312 Firefox/1.5.0.11",
	"Mozilla/5.0 (Windows; U; Windows NT 5.0; zh-CN;; rv:1.8.0.11) Gecko/20070312 Firefox/1.5.0.11",
	"Mozilla/5.0 (Windows; U; Windows NT 5.0;; zh-CN; rv:1.8.0.11) Gecko/20070312 Firefox/1.5.0.11",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.8.0.10pre) Gecko/20070211 Firefox/1.5.0.10pre",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1;; zh-CN; rv:1.8.0.10) Gecko/20070216 Firefox/1.5.0.10",
	"Mozilla/5.0 (Windows NT 5.2; U;; zh-CN; rv:1.8.0) Gecko/20060728 Firefox/1.5.0",
	"Mozilla/5.0 (Windows NT 5.1; U;; zh-CN; rv:1.8.0) Gecko/20060728 Firefox/1.5.0",
	"Mozilla/5.0 (Windows; zh-CN; U;; zh-CN; rv:1.8.0) Gecko/20060728 Firefox/1.5.0",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1;; zh-CN; rv:1.8b5) Gecko/20051006 Firefox/1.4.1",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.8b5) Gecko/20051006 Firefox/1.4.1",
	"Mozilla/5.0 (Windows; U; Windows NT 5.0; zh-CN;; rv:1.8b4) Gecko/20050908 Firefox/1.4",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.7.13) Gecko/20060410 Firefox/1.0.8",
	"Mozilla/5.0 (Windows; U; WinNT4.0; zh-CN;; rv:1.7.9) Gecko/20050711 Firefox/1.0.5",
	"Mozilla/5.0 (Windows; U; Windows NT 5.2; zh-CN;; rv:1.7.9) Gecko/20050711 Firefox/1.0.5",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.7.9) Gecko/20050711 Firefox/1.0.5",
	"Mozilla/5.0 (Windows; U; Win 9x 4.90; zh-CN;; rv:1.7.9) Gecko/20050711 Firefox/1.0.5",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.7.7) Gecko/20050414 Firefox/1.0.3",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.7.7) Gecko/20050414 Firefox/1.0.3",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.7.7) Gecko/20050414 Firefox/1.0.3",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.7.7) Gecko/20050414 Firefox/1.0.3",
	"Mozilla/5.0 (Windows; U; Windows NT 5.0; zh-CN;; rv:1.7.7) Gecko/20050414 Firefox/1.0.3",
	"Mozilla/5.0 (Windows; U; Win98; zh-CN;; rv:1.7.7) Gecko/20050414 Firefox/1.0.3",
	"Mozilla/5.0 (Windows; U; Win98; zh-CN;; rv:1.7.7) Gecko/20050414 Firefox/1.0.3",
	"Mozilla/5.0 (Windows; U; Windows NT 5.2; zh-CN;; rv:1.7.6) Gecko/20050321 Firefox/1.0.2",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.7.6) Gecko/20050318 Firefox/1.0.2",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.7.6) Gecko/20050318 Firefox/1.0.2",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.7.6) Gecko/20050318 Firefox/1.0.2",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.7.6) Gecko/20050321 Firefox/1.0.2",
	"Mozilla/5.0 (Windows; U; Windows NT 5.0; zh-CN;; rv:1.7.6) Gecko/20050317 Firefox/1.0.2",
	"Mozilla/5.0 (Windows; U; Windows NT 5.0; zh-CN;; rv:1.7.6) Gecko/20050321 Firefox/1.0.2",
	"Mozilla/5.0 (Windows; U; WinNT4.0; zh-CN;; rv:1.7.6) Gecko/20050226 Firefox/1.0.1",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.7.6) Gecko/20050225 Firefox/1.0.1",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.7.6) Gecko/20050226 Firefox/1.0.1",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.7.6) Gecko/20050223 Firefox/1.0.1",
	"Mozilla/5.0 (Windows; U; Windows NT 5.0; zh-CN;; rv:1.7.6) Gecko/20050226 Firefox/1.0.1",
	"Mozilla/5.0 (Windows; U; Windows NT 5.0; zh-CN;; rv:1.6) Gecko/20040206 Firefox/1.0.1",
	"Mozilla/5.0 (Windows; U; Win98; zh-CN;; rv:1.7.6) Gecko/20050225 Firefox/1.0.1",
	"Mozilla/5.0 (Windows; U; WinNT4.0; zh-CN;; rv:1.7.5) Gecko/20041108 Firefox/1.0",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1;; zh-CN; rv:1.7) Gecko/20040803 Firefox/0.9.3",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.7) Gecko/20040803 Firefox/0.9.3",
	"Mozilla/5.0 (Windows; U; Windows NT 5.0; zh-CN;; rv:1.7) Gecko/20040803 Firefox/0.9.3",
	"Mozilla/5.0 (Windows; U; Win 9x 4.90; rv:1.7) Gecko/20040803 Firefox/0.9.3",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.7) Gecko/20040707 Firefox/0.9.2",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.7) Gecko/20040626 Firefox/0.9.1",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.7) Gecko/20040614 Firefox/0.9",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.6) Gecko/20040206 Firefox/0.8",
	"Mozilla/5.0 (Windows; U; Windows NT 5.0; zh-CN;; rv:1.6) Gecko/20040206 Firefox/0.8",
	"Mozilla/5.0 (Windows; U; Win98; zh-CN;; rv:1.6) Gecko/20040206 Firefox/0.8",
	"Mozilla/5.0 (Windows; U; Windows NT 5.2; rv:1.7.3) Gecko/20041001 Firefox/0.10.1",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; rv:1.7.3) Gecko/20040913 Firefox/0.10.1",
	"Mozilla/5.0 (Windows; U; Windows NT 5.0; rv:1.7.3) Gecko/20041001 Firefox/0.10.1",
	"Mozilla/5.0 (Windows; U; Win98; rv:1.7.3) Gecko/20041001 Firefox/0.10.1",
	"Mozilla/5.0 (Windows; U; Windows NT 5.0; zh-CN;; rv:1.8.0.1) Gecko/20060111 Firefox/0.10",
	"Mozilla/5.0 (Windows; U; Win98; rv:1.7.3) Gecko/20040913 Firefox/0.10",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.9) Gecko/20080705 Firefox/3.0 Kapiko/3.0",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.9.1b3pre) Gecko/20090206 Minefield/3.1b2pre Firefox/3.0.3",
	"Mozilla/5.0 (Windows; U; Windows NT 6.1; zh-CN;; rv:1.9.2.13) Gecko/20101210 Namoroka/3.6.13 Firefox/3.6.12",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7 Prism/1.0b2",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.8.1.22) Gecko/20090605 SeaMonkey/1.1.17 Firefox/3.0.10",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN;; rv:1.9.1.6) Gecko/20100121 Firefox/3.5.6 Wyzo/3.5.6",
	"Mozilla/5.0 (Windows; U; Windows NT 6.1; zh-CN;; rv:1.9.0.9) Gecko/2009042410 Firefox/3.0.9 Wyzo/3.0.3",
	"Mozilla/5.0 (Windows; U; Windows NT 5.2; zh-CN;; rv:1.9.0.9) Gecko/2009042410 Firefox/3.0.9 Wyzo/3.0.3",
	"Mozilla/5.0 (Windows; U; Windows NT 6.0; zh-CN;; rv:1.8.1.6) Gecko/20070801 Firefox/2.0 Wyzo/0.5.3",
}

// RandomUserAgent  随机返回一个带时间戳的UA
func RandomUserAgent() string {
	rand.Seed(time.Now().UnixNano())
	i := rand.Intn(len(userAgents))
	return userAgents[i] + " Time/" + strconv.FormatInt(time.Now().UnixMilli(), 10)
}

/*
取到icon hash
参考了 appfinger https://github.com/lcvvvv/appfinger/tree/main
跟fofa 一样的icon_hash计算方式,通用语法
*/
var isUint32 bool

func standBase64(braw []byte) []byte {
	bckd := base64.StdEncoding.EncodeToString(braw)
	var buffer bytes.Buffer
	for i := 0; i < len(bckd); i++ {
		ch := bckd[i]
		buffer.WriteByte(ch)
		// 每76个字符加一个换行
		if (i+1)%76 == 0 {
			buffer.WriteByte('\n')
		}
	}
	buffer.WriteByte('\n')
	return buffer.Bytes()
}

// mmh3 hash 处理
func mmh3Hash32(raw []byte) string {
	var h32 = murmur3.New32()
	_, _ = h32.Write(raw)
	//支持有符号,默认无符号
	if isUint32 {
		return fmt.Sprintf("%d", h32.Sum32())
	}
	return fmt.Sprintf("%d", int32(h32.Sum32()))
}

func Encode(buf []byte) string {
	return mmh3Hash32(standBase64(buf))
}

func post(url string) (*http.Request, error) {
	data, err := config.GetPostData()
	if err != nil {
		log.Println(err)
		data = []byte{} //置空
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	headers, err := config.GetHeaders()
	if err != nil {
		log.Printf("config 请求头解析错误 %v", err)
		// 自清理
		for k := range headers {
			headers.Del(k)
		}
	}
	//加一组新的ua
	headers.Set("User-Agent", RandomUserAgent())
	req.Header = headers
	return req, nil
}

func get(url string) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	headers, err := config.GetHeaders()
	if err != nil {
		log.Printf("config 请求头解析错误 %v", err)
		// 自清理
		for k := range headers {
			headers.Del(k)
		}
	}
	//加一组新的ua
	headers.Set("User-Agent", RandomUserAgent())
	req.Header = headers
	return req, nil
}
func headerToString(header http.Header) string {
	var sb strings.Builder
	for key, values := range header {
		for _, value := range values {
			sb.WriteString(key)
			sb.WriteString(": ")
			sb.WriteString(value)
			sb.WriteString("\r\n")
		}
	}
	return sb.String()
}

// GetIconHash 接收一个resp.Body
func (target *Target) getIconHash() (string, error) {
	resp, err := http.Get(target.U.Scheme + "://" + target.U.Host + "/favicon.ico")
	if err != nil {
		return "", err
	}
	body, err := io.ReadAll(resp.Body)
	return mmh3Hash32(standBase64(body)), err
}

// 根据target 解析出指纹数据
func (target *Target) extract(response *http.Response) (*fingerprints.ResponseData, error) {
	responseData := &fingerprints.ResponseData{} //记得初始化指针啊
	//var responseData *fingerprints.ResponseData //这样是错误的,指针没有初始化,后面不能直接赋值
	hash, err := target.getIconHash()
	if err != nil {
		hash = ""
	}
	responseData.Hash = hash
	body, _ := io.ReadAll(response.Body)
	responseData.Body = string(body)
	if responseData.Body == "" {
		responseData.Host = target.U.Host
		responseData.Headers = headerToString(response.Header)
		return responseData, nil
	}
	responseData.Host = target.U.Host
	responseData.Headers = headerToString(response.Header)
	responseData.ICP = getICP(responseData.Body)
	responseData.BodyLength = len(body)
	responseData.Title, _ = GetTitle(responseData.Body)

	return responseData, nil
}

// GetTitle 提取 HTML 中的 <title> 内容
func GetTitle(body string) (string, error) {
	// 正则提取 <title> 标签内容（忽略大小写）
	re := regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)
	match := re.FindStringSubmatch(body)
	if len(match) > 1 {
		// 清理前后空白
		return strings.TrimSpace(match[1]), nil
	}
	return "", nil // 没有 <title> 标签
}

var (
	provinces = []string{
		"京", "津", "冀", "晋", "蒙", "辽", "吉", "黑",
		"沪", "苏", "浙", "皖", "闽", "赣", "鲁", "豫",
		"湘", "粤", "桂", "琼", "川", "蜀", "贵", "黔",
		"云", "滇", "渝", "藏", "陕", "秦", "甘", "陇",
		"青", "宁", "新", "港", "澳", "台", "鄂",
	}
	provincesString = strings.Join(provinces, "|")
	icpRegx         = regexp.MustCompile(`(?:` + provincesString + `)ICP备\s*\d+号(?:-\d+)?`)
)

func getICP(body string) string {
	if icpRegx.MatchString(body) == true {
		return icpRegx.FindString(body)
	}
	return ""
}

// Request 后的结果拿去给做指纹匹配
// 组合target和responseData得到一个banner
// 然后用于指纹匹配,交付最终的结果处理
func (target *Target) Request() (*models.Banner, error) {
	banner := &models.Banner{}
	banner.CompiledRule = target.CompiledRule
	if target.CompiledRule.IsPost {
		//	post
		req, err := post(target.U.Scheme + "://" + target.U.Host + target.CompiledRule.Path)
		if err != nil {
			return nil, err
		}
		transport, err := config.GetProxy()
		if err != nil {
			return nil, err
		}
		client := &http.Client{Transport: transport}
		resp, err := client.Do(req)
		//处理返回body为空的时候
		if err != nil {
			log.Printf("请求错误 %v\n", err)
			if banner.ResponseData == nil {
				banner.ResponseData = &fingerprints.ResponseData{}
			}
			banner.ResponseData.Host = target.U.Host
			return banner, err
		}
		defer resp.Body.Close()
		responseData, err := target.extract(resp)
		if err != nil {
			return nil, err
		}
		banner.ResponseData = responseData
		return banner, nil
	} else {
		//get
		req, err := get(target.U.Scheme + "://" + target.U.Host + target.CompiledRule.Path)
		if err != nil {
			return nil, err
		}
		transport, err := config.GetProxy()
		if err != nil {
			return nil, err
		}
		client := &http.Client{Transport: transport}
		resp, err := client.Do(req)
		//处理返回body为空的时候
		if err != nil {
			log.Printf("请求错误 %v\n", err)
			if banner.ResponseData == nil {
				banner.ResponseData = &fingerprints.ResponseData{}
			}
			banner.ResponseData.Host = target.U.Host
			return banner, err
		}
		defer resp.Body.Close()
		responseData, err := target.extract(resp)
		if err != nil {
			return nil, err
		}
		banner.ResponseData = responseData
		return banner, nil
	}
}
