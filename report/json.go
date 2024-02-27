package report

import (
	"github.com/ztelliot/taierspeed-cli/defs"
	"time"
)

// JSONReport represents the output data fields in a JSON file
type JSONReport struct {
	Timestamp     time.Time           `json:"timestamp"`
	Server        Server              `json:"server"`
	Client        defs.IPInfoResponse `json:"client"`
	BytesSent     uint64              `json:"bytes_sent"`
	BytesReceived uint64              `json:"bytes_received"`
	Ping          float64             `json:"ping"`
	Jitter        float64             `json:"jitter"`
	Upload        float64             `json:"upload"`
	Download      float64             `json:"download"`
}

// Server represents the speed test server's information
type Server struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	IP       string `json:"ip"`
	Province string `json:"province"`
	City     string `json:"city"`
	ISP      string `json:"isp"`
}
