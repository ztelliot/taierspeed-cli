package defs

var (
	BuildDate   string
	ProgName    string
	ProgVersion string
	UserAgent   = "Dalvik/2.1.0 (Linux; U; Android 13; LE2120 Build/TP1A.220624.014)"
	IMEI        = "TS848B4F0BD74FE799"
)

type IPInfoResponse struct {
	IP      string
	Area    string
	City    string
	Region  string
	Country string
	Isp     string
}
