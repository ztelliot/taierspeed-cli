package defs

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"
)

var (
	BuildDate   string
	ProgName    string
	ProgVersion string
	Brand       = "OnePlus"
	DeviceID    = "b721c5a0dba37004"
	Model       = "NE2210"
	OS          = "Android 14"
	GenexUA     = fmt.Sprintf("com.huawei.genexcloud.speedtest/4.6.0.302 (Linux; %s; %s) RestClient/6.0.6.300", OS, Model)
	AndroidUA   = fmt.Sprintf("Dalvik/2.1.0 (Linux; U; %s; %s Build/TP1A.220624.014)", OS, Model)
	BrowserUA   = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.60 Safari/537.36"
)

type IPInfoResponse struct {
	IP       string `json:"ip"`
	District string `json:"district"`
	City     string `json:"city"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	Isp      string `json:"isp"`
}

type ProvinceInfo struct {
	ID    string `csv:"id"`
	Code  string `csv:"code"`
	Short string `csv:"short"`
	Name  string `csv:"name"`
	Lon   string `csv:"lon"`
	Lat   string `csv:"lat"`
}

var (
	GUANGDONG = ProvinceInfo{"44", "gd", "广东", "广东省", "113.266887", "23.133306"}
	DEFPROV   = ProvinceInfo{"", "uk", "未知", "未知", "0", "0"}
)

type ISPInfo struct {
	ID   string `csv:"id"`
	Code string `csv:"code"`
	Name string `csv:"name"`
}

var (
	CHINANET = ISPInfo{ID: "4134", Code: "CHINANET", Name: "电信"}
	CERNET   = ISPInfo{ID: "4538", Code: "CERNET", Name: "教育网"}
	UNICOM   = ISPInfo{ID: "4837", Code: "UNICOM", Name: "联通"}
	CHINABTN = ISPInfo{ID: "7641", Code: "CHINABTN", Name: "广电网"}
	CMCC     = ISPInfo{ID: "9808", Code: "CMCC", Name: "移动"}
	DXTNET   = ISPInfo{ID: "17964", Code: "DXTNET", Name: "鹏博士"}
	DEFISP   = ISPInfo{ID: "", Code: "UNKNOWN", Name: "未知"}
)

type GDPayload struct {
	Brand     string `json:"c_brand"`
	IMEI      string `json:"c_imei"`
	Model     string `json:"c_model"`
	Network   int    `json:"c_network"`
	OS        string `json:"c_os"`
	Type      int    `json:"c_type"`
	Version   string `json:"c_version"`
	Nonce     string `json:"nonce"`
	Sign      string `json:"sign"`
	Timestamp string `json:"timestamp"`
}

func (g *GDPayload) Init() {
	time.Local, _ = time.LoadLocation("Asia/Chongqing")

	g.Brand = Brand
	g.IMEI = DeviceID
	g.Model = Model
	g.Network = 1
	g.OS = OS
	g.Type = 2
	g.Version = "1.5.1"
	g.Timestamp = strconv.Itoa(int(time.Now().Local().UnixMilli()))

	md5Payload := ""
	sVal := reflect.ValueOf(g)
	sType := reflect.TypeOf(g)
	if sType.Kind() == reflect.Ptr {
		sVal = sVal.Elem()
		sType = sType.Elem()
	}
	for i := 0; i < sVal.NumField(); i++ {
		val := sVal.Field(i)
		str := ""
		switch val.Kind() {
		case reflect.String:
			str = val.String()
		case reflect.Int:
			str = strconv.Itoa(int(val.Int()))
		}
		if str != "" {
			md5Payload += fmt.Sprintf("%s=%s&", sType.Field(i).Tag.Get("json"), str)
		}
	}
	md5Payload += "key=a32e(-.-)rx234xo"
	md5Ctx := md5.New()
	md5Ctx.Write([]byte(md5Payload))
	g.Sign = strings.ToUpper(hex.EncodeToString(md5Ctx.Sum(nil)))
}
