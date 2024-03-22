package defs

import (
	"fmt"
)

var (
	BuildDate   string
	ProgName    string
	ProgVersion string
	Model       = "NE2210"
	OS          = "Android 14"
	AndroidUA   = fmt.Sprintf("Dalvik/2.1.0 (Linux; U; %s; %s Build/TP1A.220624.014)", OS, Model)
	BrowserUA   = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.60 Safari/537.36"
)

type Group struct {
	Province string
	ISP      uint8
}

type ISPInfo struct {
	ID    uint8
	ASN   uint16
	Short string
	Code  string
	Name  string
}

var (
	TELECOM = ISPInfo{1, 4134, "ct", "TELECOM", "电信"}
	CERNET  = ISPInfo{4, 4538, "cernet", "CERNET", "教育网"}
	UNICOM  = ISPInfo{2, 4837, "cu", "UNICOM", "联通"}
	CATV    = ISPInfo{5, 7641, "catv", "CHINABTN", "广电网"}
	MOBILE  = ISPInfo{3, 9808, "cm", "MOBILE", "移动"}
	DRPENG  = ISPInfo{6, 17964, "drpeng", "DXTNET", "鹏博士"}
	DEFISP  = ISPInfo{0, 0, "uk", "UNKNOWN", "未知"}
	ISPMap  = map[uint8]*ISPInfo{
		TELECOM.ID: &TELECOM,
		CERNET.ID:  &CERNET,
		UNICOM.ID:  &UNICOM,
		CATV.ID:    &CATV,
		MOBILE.ID:  &MOBILE,
		DRPENG.ID:  &DRPENG,
		DEFISP.ID:  &DEFISP,
	}
)
