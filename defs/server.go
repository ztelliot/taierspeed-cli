package defs

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/briandowns/spinner"
	"github.com/prometheus-community/pro-bing"
	log "github.com/sirupsen/logrus"
)

type ServerType uint8

const (
	GlobalSpeed ServerType = iota
	Perception
	WirelessSpeed
	StaticFile
)

// Server represents a speed test server
type Server struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	IP          string     `json:"ip"`
	IPv6        string     `json:"ipv6"`
	Target      string     `json:"-"`
	Host        string     `json:"host"`
	Port        uint16     `json:"port"`
	HTTPS       bool       `json:"https"`
	Prov        uint8      `json:"province"`
	Province    string     `json:"-"`
	City        string     `json:"city"`
	ISP         uint8      `json:"isp"`
	DownloadURI string     `json:"download"`
	UploadURI   string     `json:"upload"`
	PingURI     string     `json:"ping"`
	Type        ServerType `json:"type"`
	PingType    PingType   `json:"-"`
}

func (s *Server) GetHost() string {
	if s.Port != 80 && s.Port != 443 {
		return net.JoinHostPort(s.Host, strconv.Itoa(int(s.Port)))
	} else {
		return s.Host
	}
}

func (s *Server) URL() *url.URL {
	scheme := "http"
	if s.HTTPS {
		scheme = "https"
	}
	u := url.URL{
		Scheme: scheme,
		Host:   net.JoinHostPort(s.Target, strconv.Itoa(int(s.Port))),
		Path:   "/",
	}
	return &u
}

func (s *Server) DownloadURL() *url.URL {
	if s.DownloadURI != "" {
		return s.URL().JoinPath(s.DownloadURI)
	} else {
		switch s.Type {
		case GlobalSpeed:
			return s.URL().JoinPath("/speed/File(1G).dl")
		case Perception:
			return s.URL().JoinPath("/speedtest/download")
		case WirelessSpeed:
			return s.URL().JoinPath("/GSpeedTestServer/download")
		default:
			return s.URL()
		}
	}
}

func (s *Server) UploadURL() *url.URL {
	if s.UploadURI != "" {
		return s.URL().JoinPath(s.UploadURI)
	} else {
		switch s.Type {
		case GlobalSpeed:
			return s.URL().JoinPath("/speed/doAnalsLoad.do")
		case Perception:
			return s.URL().JoinPath("/speedtest/upload")
		case WirelessSpeed:
			return s.URL().JoinPath("/GSpeedTestServer/upload")
		default:
			return s.URL()
		}
	}
}

func (s *Server) PingURL() *url.URL {
	if s.PingURI != "" {
		return s.URL().JoinPath(s.PingURI)
	} else {
		switch s.Type {
		case GlobalSpeed:
			return s.URL().JoinPath("/speed/")
		case Perception:
			return s.URL().JoinPath("/speedtest/ping")
		case WirelessSpeed:
			return s.URL().JoinPath("/GSpeedTestServer/")
		default:
			return s.URL()
		}
	}
}

// IsUp checks the speed test backend is up by accessing the ping URL
func (s *Server) IsUp() bool {
	req, err := http.NewRequest(http.MethodGet, s.PingURL().String(), nil)
	if err != nil {
		log.Debugf("Failed when creating HTTP request: %s", err)
		return false
	}

	if s.Host != "" {
		req.Host = s.GetHost()
	}
	req.Header.Set("User-Agent", AndroidUA)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Debugf("Error checking for server status: %s", err)
		return false
	}
	defer resp.Body.Close()

	// only return online if the ping URL returns nothing and 200
	return (resp.StatusCode == http.StatusOK) || (resp.StatusCode == http.StatusForbidden) || (resp.StatusCode == http.StatusNotFound) || (resp.StatusCode == http.StatusBadGateway)
}

// ICMPPingAndJitter pings the server via ICMP echos and calculate the average ping and jitter
func (s *Server) ICMPPingAndJitter(count int, srcIp, network string) (float64, float64, error) {
	if s.PingType == HTTP {
		return s.PingAndJitter(count + 2)
	}

	p := probing.New(s.Target)
	if s.PingType == ICMP {
		p.SetPrivileged(true)
	}
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
		return s.PingAndJitter(count + 2)
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
		s.PingType = HTTP
		log.Debugf("No ICMP/UDP pings returned for server %s (%s), trying TCP ping", s.Name, s.ID)
		return s.PingAndJitter(count + 2)
	}

	return float64(stats.AvgRtt.Milliseconds()), jitter, nil
}

// PingAndJitter pings the server via accessing ping URL and calculate the average ping and jitter
func (s *Server) PingAndJitter(count int) (float64, float64, error) {
	var pings []float64

	req, err := http.NewRequest(http.MethodGet, s.PingURL().String(), nil)
	if err != nil {
		log.Debugf("Failed when creating HTTP request: %s", err)
		return 0, 0, err
	}

	if s.Host != "" {
		req.Host = s.GetHost()
	}
	req.Header.Set("User-Agent", AndroidUA)

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
func (s *Server) Download(silent, useBytes, useMebi bool, requests int, duration time.Duration, token string) (float64, uint64, error) {
	counter := NewCounter()
	counter.SetMebi(useMebi)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	uri := s.DownloadURL()
	if s.Type == GlobalSpeed {
		uri.RawQuery = fmt.Sprintf("key=%s", token)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri.String(), nil)
	if err != nil {
		log.Debugf("Failed when creating HTTP request: %s", err)
		return 0, 0, err
	}

	if s.Host != "" {
		req.Host = s.GetHost()
	}
	req.Header.Set("User-Agent", BrowserUA)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "close")

	downloadDone := make(chan struct{}, requests)

	doDownload := func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && !os.IsTimeout(err) {
				log.Debugf("Failed when making HTTP request: %s", err)
			}
		} else {
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				log.Debugf("Failed to test download speed: %s", resp.Status)
				return
			}

			if _, err = io.Copy(io.Discard, io.TeeReader(resp.Body, counter)); err != nil {
				if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && !os.IsTimeout(err) {
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
func (s *Server) Upload(noPrealloc, silent, useBytes, useMebi bool, requests, uploadSize int, duration time.Duration, token string) (float64, uint64, error) {
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.UploadURL().String(), counter)
	if err != nil {
		log.Debugf("Failed when creating HTTP request: %s", err)
		return 0, 0, err
	}

	if s.Host != "" {
		req.Host = s.GetHost()
	}
	req.Header.Set("User-Agent", AndroidUA)
	if s.Type != WirelessSpeed {
		req.Header.Set("Connection", "close")
		req.Header.Set("Charset", "UTF-8")
		req.Header.Set("Key", token)
		req.Header.Set("Content-Type", "multipart/form-data;boundary=00content0boundary00")
	} else {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	uploadDone := make(chan struct{}, requests)

	doUpload := func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && !os.IsTimeout(err) {
				log.Debugf("Failed when making HTTP request: %s", err)
			}
		} else {
			defer resp.Body.Close()
			if _, err := io.Copy(io.Discard, resp.Body); err != nil {
				if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && !os.IsTimeout(err) {
					log.Debugf("Failed when reading HTTP response: %s", err)
				}
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
