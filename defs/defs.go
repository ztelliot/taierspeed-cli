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
	IP          string `json:"ip"`
	Area        string `json:"district"`
	City        string `json:"city"`
	Region      string `json:"province"`
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
	Isp         string `json:"isp"`
	Lon         string `json:"lon"`
	Lat         string `json:"lat"`
}
