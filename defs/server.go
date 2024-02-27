package defs

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	"github.com/go-ping/ping"
	log "github.com/sirupsen/logrus"
)

type ServerGlobal struct {
	ID   int    `json:"hostid,string"`
	Name string `json:"hostname"`
	IP   string `json:"hostip"`
	Port string `json:"port"`
	Prov string `json:"pname"`
	City string `json:"city"`
	ISP  string `json:"oper,omitempty"`
}

type ServerWireless struct {
	ID     int    `json:"s_id"`
	Name   string `json:"s_name"`
	IP     string `json:"s_ip"`
	IPv6   string `json:"s_ipv6"`
	URL    string `json:"s_url"`
	URLs   string `json:"s_url_https"`
	URLv6  string `json:"s_url_ipv6"`
	County string `json:"s_county"`
	City   string `json:"s_city"`
	Prov   string `json:"s_province"`
	ISP    int    `json:"s_operator"`
}

func (s *ServerWireless) GetISP() string {
	switch s.ISP {
	case 1:
		return "移动"
	case 2:
		return "联通"
	case 3:
		return "电信"
	default:
		return ""
	}
}

type ServerType uint8

const (
	GlobalSpeed ServerType = iota
	Perception
	WirelessSpeed
)

// Server represents a speed test server
type Server struct {
	ID   int    `json:"id"`
	Name string `json:"server_name"`
	IP   string `json:"server_ip"`
	IPv6 string `json:"-"`
	Port string `json:"-"`

	Province string `json:"province"`
	City     string `json:"city"`
	ISP      string `json:"-"`

	URL         string `json:"-"`
	URLv6       string `json:"-"`
	DownloadURL string `json:"http_downloadUrl"`
	UploadURL   string `json:"http_uploadUrl"`
	PingURL     string `json:"ping_url"`

	HwType            int    `json:"hw_type"`
	HwPingHeaders     string `json:"hw_httpPingHeaders"`
	HwDownloadHeaders string `json:"hw_httpDlHeaders"`
	HwUploadHeaders   string `json:"hw_httpUlHeaders"`

	NoICMP bool       `json:"-"`
	Type   ServerType `json:"protocol_type"`
}

func (s *Server) ShowCity() string {
	if strings.Contains(s.Province, s.City) {
		return fmt.Sprintf("%s-%s", s.Province, s.ISP)
	} else {
		return fmt.Sprintf("%s-%s-%s", s.Province, s.City, s.ISP)
	}
}

// IsUp checks the speed test backend is up by accessing the ping URL
func (s *Server) IsUp(network string) bool {
	var target string

	switch s.Type {
	case Perception:
		target = s.PingURL
	case WirelessSpeed:
		switch network {
		case "ip6":
			target = s.URLv6
		default:
			target = s.URL
		}
	default:
		target = fmt.Sprintf("http://%s:%s/speed/", s.IP, s.Port)
	}

	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		log.Debugf("Failed when creating HTTP request: %s", err)
		return false
	}

	if s.HwType == 1 {
		req.Host = s.HwPingHeaders
		req.Header.Set("User-Agent", GenexUA)
	} else {
		req.Header.Set("User-Agent", AndroidUA)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Debugf("Error checking for server status: %s", err)
		return false
	}
	defer resp.Body.Close()

	// only return online if the ping URL returns nothing and 200
	return (resp.StatusCode == http.StatusOK) || (resp.StatusCode == http.StatusForbidden)
}

// ICMPPingAndJitter pings the server via ICMP echos and calculate the average ping and jitter
func (s *Server) ICMPPingAndJitter(count int, srcIp, network string) (float64, float64, error) {
	if s.NoICMP {
		log.Debugf("Skipping ICMP for server %s, will use HTTP ping", s.Name)
		return s.PingAndJitter(count+2, network)
	}

	var target string

	switch s.Type {
	case Perception:
		if s.URL != "" {
			target = s.URL
		} else {
			target = s.IP
		}
	case WirelessSpeed:
		switch network {
		case "ip6":
			target = s.IPv6
		default:
			if u, err := url.Parse(s.URL); err != nil {
				log.Debugf("Failed when parsing server URL: %s", err)
				return 0, 0, err
			} else {
				target = u.Hostname()
			}
		}
	default:
		target = s.IP
	}

	p, err := ping.NewPinger(target)
	if err != nil {
		log.Debugf("ICMP ping failed: %s, will use HTTP ping", err)
		return s.PingAndJitter(count+2, network)
	}
	p.SetPrivileged(true)
	p.SetNetwork(network)
	p.Count = count
	p.Timeout = time.Duration(count) * time.Second
	if srcIp != "" {
		p.Source = srcIp
	}
	if log.GetLevel() == log.DebugLevel {
		p.Debug = true
	}
	if err := p.Run(); err != nil {
		log.Debugf("Failed to ping target host: %s", err)
		log.Debug("Will try TCP ping")
		return s.PingAndJitter(count+2, network)
	}

	stats := p.Statistics()

	var lastPing, jitter float64
	for idx, rtt := range stats.Rtts {
		if idx != 0 {
			instJitter := math.Abs(lastPing - float64(rtt.Milliseconds()))
			if idx > 1 {
				if jitter > instJitter {
					jitter = jitter*0.7 + instJitter*0.3
				} else {
					jitter = instJitter*0.2 + jitter*0.8
				}
			}
		}
		lastPing = float64(rtt.Milliseconds())
	}

	if len(stats.Rtts) == 0 {
		s.NoICMP = true
		log.Debugf("No ICMP pings returned for server %s (%s), trying TCP ping", s.Name, s.IP)
		return s.PingAndJitter(count+2, network)
	}

	return float64(stats.AvgRtt.Milliseconds()), jitter, nil
}

// PingAndJitter pings the server via accessing ping URL and calculate the average ping and jitter
func (s *Server) PingAndJitter(count int, network string) (float64, float64, error) {
	var target string

	switch s.Type {
	case Perception:
		target = s.PingURL
	case WirelessSpeed:
		switch network {
		case "ip6":
			target = s.URLv6
		default:
			target = s.URL
		}
	default:
		target = fmt.Sprintf("http://%s:%s/speed/", s.IP, s.Port)
	}

	var pings []float64

	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		log.Debugf("Failed when creating HTTP request: %s", err)
		return 0, 0, err
	}
	if s.HwType == 1 {
		req.Host = s.HwPingHeaders
		req.Header.Set("User-Agent", GenexUA)
	} else {
		req.Header.Set("User-Agent", AndroidUA)
	}

	for i := 0; i < count; i++ {
		start := time.Now()
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Debugf("Failed when making HTTP request: %s", err)
			return 0, 0, err
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		pings = append(pings, float64(time.Since(start).Milliseconds()))
	}

	// discard first result due to handshake overhead
	if len(pings) > 1 {
		pings = pings[1:]
	}

	var lastPing, jitter float64
	for idx, p := range pings {
		if idx != 0 {
			instJitter := math.Abs(lastPing - p)
			if idx > 1 {
				if jitter > instJitter {
					jitter = jitter*0.7 + instJitter*0.3
				} else {
					jitter = instJitter*0.2 + jitter*0.8
				}
			}
		}
		lastPing = p
	}

	return getAvg(pings), jitter, nil
}

// Download performs the actual download test
func (s *Server) Download(silent, useBytes, useMebi bool, requests int, duration time.Duration, network, token string) (float64, uint64, error) {
	counter := NewCounter()
	counter.SetMebi(useMebi)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var uri string
	switch s.Type {
	case Perception:
		uri = s.DownloadURL
	case WirelessSpeed:
		switch network {
		case "ip6":
			uri = s.URLv6
		default:
			uri = s.URL
		}
		uri = fmt.Sprintf("%s/download", uri)
	default:
		uri = fmt.Sprintf("http://%s:%s/speed/File(1G).dl?key=%s", s.IP, s.Port, token)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		log.Debugf("Failed when creating HTTP request: %s", err)
		return 0, 0, err
	}

	if s.HwType == 1 {
		req.Host = s.HwDownloadHeaders
		req.Header.Set("User-Agent", GenexUA)
	} else {
		req.Header.Set("User-Agent", BrowserUA)
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Connection", "close")
	}

	downloadDone := make(chan struct{}, requests)

	doDownload := func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Debugf("Failed when making HTTP request: %s", err)
		} else {
			defer resp.Body.Close()

			if _, err = io.Copy(io.Discard, io.TeeReader(resp.Body, counter)); err != nil {
				if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
					log.Debugf("Failed when reading HTTP response: %s", err)
				}
			}

			downloadDone <- struct{}{}
		}
	}

	counter.Start()
	if !silent {
		pb := spinner.New(spinner.CharSets[11], 100*time.Millisecond)
		pb.Prefix = "Downloading...  "
		pb.PostUpdate = func(s *spinner.Spinner) {
			if useBytes {
				s.Suffix = fmt.Sprintf("  %s", counter.AvgHumanize())
			} else {
				s.Suffix = fmt.Sprintf("  %.2f Mbps", counter.AvgMbps())
			}
		}

		pb.Start()
		defer func() {
			if useBytes {
				pb.FinalMSG = fmt.Sprintf("Download:\t%s\n (data used: %s)", counter.AvgHumanize(), counter.BytesHumanize())
			} else {
				pb.FinalMSG = fmt.Sprintf("Download:\t%.2f Mbps (data used: %.2f MB)\n", counter.AvgMbps(), counter.MBytes())
			}
			pb.Stop()
		}()
	}

	for i := 0; i < requests; i++ {
		go doDownload()
		time.Sleep(200 * time.Millisecond)
	}
	timeout := time.After(duration)
Loop:
	for {
		select {
		case <-timeout:
			ctx.Done()
			break Loop
		case <-downloadDone:
			go doDownload()
		}
	}

	return counter.AvgMbps(), counter.Total(), nil
}

// Upload performs the actual upload test
func (s *Server) Upload(noPrealloc, silent, useBytes, useMebi bool, requests, uploadSize int, duration time.Duration, network, token string) (float64, uint64, error) {
	counter := NewCounter()
	counter.SetMebi(useMebi)
	counter.SetUploadSize(uploadSize)

	if noPrealloc {
		log.Info("Pre-allocation is disabled, performance might be lower!")
		counter.reader = &SeekWrapper{rand.Reader}
	} else {
		counter.GenerateBlob()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var uri string
	switch s.Type {
	case Perception:
		uri = s.UploadURL
	case WirelessSpeed:
		switch network {
		case "ip6":
			uri = s.URLv6
		default:
			uri = s.URL
		}
		uri = fmt.Sprintf("%s/upload", uri)
	default:
		uri = fmt.Sprintf("http://%s:%s/speed/doAnalsLoad.do", s.IP, s.Port)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, counter)
	if err != nil {
		log.Debugf("Failed when creating HTTP request: %s", err)
		return 0, 0, err
	}

	if s.HwType == 1 {
		req.Host = s.HwUploadHeaders
		req.Header.Set("User-Agent", GenexUA)
	} else {
		req.Header.Set("User-Agent", AndroidUA)
		if s.Type != WirelessSpeed {
			req.Header.Set("Connection", "close")
			req.Header.Set("Charset", "UTF-8")
			req.Header.Set("Key", token)
			req.Header.Set("Content-Type", "multipart/form-data;boundary=00content0boundary00")
		} else {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	uploadDone := make(chan struct{}, requests)

	doUpload := func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			log.Debugf("Failed when making HTTP request: %s", err)
		} else if err == nil {
			defer resp.Body.Close()
			if _, err := io.Copy(io.Discard, resp.Body); err != nil {
				log.Debugf("Failed when reading HTTP response: %s", err)
			}

			uploadDone <- struct{}{}
		}
	}

	counter.Start()
	if !silent {
		pb := spinner.New(spinner.CharSets[11], 100*time.Millisecond)
		pb.Prefix = "Uploading...  "
		pb.PostUpdate = func(s *spinner.Spinner) {
			if useBytes {
				s.Suffix = fmt.Sprintf("  %s", counter.AvgHumanize())
			} else {
				s.Suffix = fmt.Sprintf("  %.2f Mbps", counter.AvgMbps())
			}
		}

		pb.Start()
		defer func() {
			if useBytes {
				pb.FinalMSG = fmt.Sprintf("Upload:\t\t%s (data used: %s)\n", counter.AvgHumanize(), counter.BytesHumanize())
			} else {
				pb.FinalMSG = fmt.Sprintf("Upload:\t\t%.2f Mbps (data used: %.2f MB)\n", counter.AvgMbps(), counter.MBytes())
			}
			pb.Stop()
		}()
	}

	for i := 0; i < requests; i++ {
		go doUpload()
		time.Sleep(200 * time.Millisecond)
	}
	timeout := time.After(duration)
Loop:
	for {
		select {
		case <-timeout:
			ctx.Done()
			break Loop
		case <-uploadDone:
			go doUpload()
		}
	}

	return counter.AvgMbps(), counter.Total(), nil
}
