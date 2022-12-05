package defs

var (
	BuildDate   string
	ProgName    string
	ProgVersion string
	UserAgentHW = "com.huawei.genexcloud.speedtest/4.6.0.302 (Linux; Android 13; NE2210) RestClient/6.0.6.300"
	UserAgentTS = "Dalvik/2.1.0 (Linux; U; Android 13; NE2210 Build/TP1A.220624.014)"
	DeviceID    = "b721c5a0dba37004"
)

type IPInfoResponse struct {
	IP       string
	District string
	City     string
	Region   string
	Country  string
	Isp      string
}

type ProvinceInfo struct {
	ID    int    `csv:"id"`
	Code  string `csv:"code"`
	Short string `csv:"short"`
	Name  string `csv:"name"`
	Lon   string `csv:"lon"`
	Lat   string `csv:"lat"`
}
