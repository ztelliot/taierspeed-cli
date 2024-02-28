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
	ID    string
	Short string
	Code  string
	Name  string
}

var (
	TELECOM = ISPInfo{"4134", "ct", "TELECOM", "电信"}
	CERNET  = ISPInfo{"4538", "cernet", "CERNET", "教育网"}
	UNICOM  = ISPInfo{"4837", "cu", "UNICOM", "联通"}
	CATV    = ISPInfo{"7641", "catv", "CHINABTN", "广电网"}
	MOBILE  = ISPInfo{"9808", "cm", "MOBILE", "移动"}
	DRPENG  = ISPInfo{"17964", "drpeng", "DXTNET", "鹏博士"}
	DEFISP  = ISPInfo{"", "uk", "UNKNOWN", "未知"}
	ISPList = []*ISPInfo{&TELECOM, &CERNET, &UNICOM, &CATV, &MOBILE, &DRPENG}
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
