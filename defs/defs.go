package defs

var (
	BuildDate   string
	ProgName    string
	ProgVersion string
	UserAgent   = "Dalvik/2.1.0 (Linux; U; Android 13; NE2210 Build/TP1A.220624.014)"
)

type IPInfoResponse struct {
	IP      string
	Area    string
	City    string
	Region  string
	Country string
	Isp     string
}
