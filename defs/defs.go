package defs

var (
	BuildDate   string
	ProgName    string
	ProgVersion string
	UserAgentHW = "com.huawei.genexcloud.speedtest/4.6.0.302 (Linux; Android 13; NE2210) RestClient/6.0.6.300"
	UserAgentTS = "Dalvik/2.1.0 (Linux; U; Android 13; NE2210 Build/TP1A.220624.014)"
	UserAgent   = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.60 Safari/537.36"
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
	ID    string `csv:"id"`
	Code  string `csv:"code"`
	Short string `csv:"short"`
	Name  string `csv:"name"`
	Lon   string `csv:"lon"`
	Lat   string `csv:"lat"`
}
