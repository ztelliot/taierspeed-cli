package defs

import (
	"time"
)

// JSONReport represents the output data fields in a JSON file
type JSONReport struct {
	Client  IPInfoResponse `json:"client"`
	Results []Result       `json:"results"`
}

// Result represents the test's information
type Result struct {
	ID            string    `json:"id" csv:"ID"`
	Name          string    `json:"name" csv:"Name"`
	IP            string    `json:"ip" csv:"IP"`
	Province      string    `json:"province" csv:"Province"`
	City          string    `json:"city" csv:"City"`
	ISP           string    `json:"isp" csv:"ISP"`
	Timestamp     time.Time `json:"timestamp" csv:"Timestamp"`
	BytesSent     uint64    `json:"bytes_sent" csv:"Sent"`
	BytesReceived uint64    `json:"bytes_received" csv:"Received"`
	Ping          float64   `json:"ping" csv:"Ping"`
	Jitter        float64   `json:"jitter" csv:"Jitter"`
	Upload        float64   `json:"upload" csv:"Upload"`
	Download      float64   `json:"download" csv:"Download"`
}
