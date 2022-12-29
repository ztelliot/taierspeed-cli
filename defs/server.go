package defs

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net/http"
	"net/url"
	"runtime"
	"time"

	"github.com/briandowns/spinner"
	"github.com/go-ping/ping"
	log "github.com/sirupsen/logrus"
)

// Server represents a speed test server
type Server struct {
	ID   int    `json:"id"`
	Name string `json:"server_name"`
	IP   string `json:"server_ip"`
	Port string `json:"-"`

	Province string `json:"province"`
	City     string `json:"city"`

	DownloadURL string `json:"http_downloadUrl"`
	UploadURL   string `json:"http_uploadUrl"`
	PingURL     string `json:"ping_url"`

	HwType            int    `json:"hw_type"`
	HwPingHeaders     string `json:"hw_httpPingHeaders"`
	HwDownloadHeaders string `json:"hw_httpDlHeaders"`
	HwUploadHeaders   string `json:"hw_httpUlHeaders"`

	NoICMP     bool `json:"-"`
	Perception bool `json:"-"`
}

type ServerTmp struct {
	ID   int    `json:"hostid,string"`
	Name string `json:"hostname"`
	IP   string `json:"hostip"`
	Port string `json:"port"`
	Prov string `json:"pname"`
}

// IsUp checks the speed test backend is up by accessing the ping URL
func (s *Server) IsUp() bool {
	target := ""
	ua := ""
	if s.Perception {
		target = s.PingURL
		ua = UserAgentHW
	} else {
		target = fmt.Sprintf("http://%s:%s/speed/", s.IP, s.Port)
		ua = UserAgentTS
	}

	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		log.Debugf("Failed when creating HTTP request: %s", err)
		return false
	}
	req.Header.Set("User-Agent", ua)

	if s.HwType == 1 {
		req.Host = s.HwPingHeaders
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
		return s.PingAndJitter(count + 2)
	}

	target := ""

	if s.Perception {
		u, err := url.Parse(s.PingURL)
		if err != nil {
			log.Debugf("Failed when parsing server URL: %s", err)
			return 0, 0, err
		}
		target = u.Hostname()
	} else {
		target = s.IP
	}

	p, err := ping.NewPinger(target)
	p.SetNetwork(network)
	if err != nil {
		log.Debugf("ICMP ping failed: %s, will use HTTP ping", err)
		return s.PingAndJitter(count + 2)
	}

	if runtime.GOOS == "windows" {
		p.SetPrivileged(true)
	}

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
		s.NoICMP = true
		log.Debugf("No ICMP pings returned for server %s (%s), trying TCP ping", s.Name, s.IP)
		return s.PingAndJitter(count + 2)
	}

	return float64(stats.AvgRtt.Milliseconds()), jitter, nil
}

// PingAndJitter pings the server via accessing ping URL and calculate the average ping and jitter
func (s *Server) PingAndJitter(count int) (float64, float64, error) {
	target := ""
	ua := ""

	if s.Perception {
		target = s.PingURL
		ua = UserAgentHW
	} else {
		target = fmt.Sprintf("http://%s:%s/speed/", s.IP, s.Port)
		ua = UserAgentTS
	}

	var pings []float64

	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		log.Debugf("Failed when creating HTTP request: %s", err)
		return 0, 0, err
	}
	req.Header.Set("User-Agent", ua)
	if s.HwType == 1 {
		req.Host = s.HwPingHeaders
	}

	for i := 0; i < count; i++ {
		start := time.Now()
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Debugf("Failed when making HTTP request: %s", err)
			return 0, 0, err
		}
		io.Copy(ioutil.Discard, resp.Body)
		resp.Body.Close()
		end := time.Now()

		pings = append(pings, float64(end.Sub(start).Milliseconds()))
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
func (s *Server) Download(silent bool, useBytes, useMebi bool, requests int, duration time.Duration, token string) (float64, int, error) {
	counter := NewCounter()
	counter.SetMebi(useMebi)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	uri := ""
	ua := ""

	if s.Perception {
		uri = s.DownloadURL
		ua = UserAgentHW
	} else {
		uri = fmt.Sprintf("http://%s:%s/speed/File(1G).dl?key=%s", s.IP, s.Port, token)
		ua = UserAgentTS
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		log.Debugf("Failed when creating HTTP request: %s", err)
		return 0, 0, err
	}
	q := req.URL.Query()
	req.URL.RawQuery = q.Encode()
	req.Header.Set("User-Agent", ua)
	if s.HwType == 1 {
		req.Host = s.HwDownloadHeaders
	}

	downloadDone := make(chan struct{}, requests)

	doDownload := func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Debugf("Failed when making HTTP request: %s", err)
		} else {
			defer resp.Body.Close()

			if _, err = io.Copy(ioutil.Discard, io.TeeReader(resp.Body, counter)); err != nil {
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
func (s *Server) Upload(noPrealloc, silent, useBytes, useMebi bool, requests int, uploadSize int, duration time.Duration, token string) (float64, int, error) {
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

	uri := ""
	ua := ""

	if s.Perception {
		uri = s.UploadURL
		ua = UserAgentHW
	} else {
		uri = fmt.Sprintf("http://%s:%s/speed/doAnalsLoad.do", s.IP, s.Port)
		ua = UserAgentTS
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, counter)
	if err != nil {
		log.Debugf("Failed when creating HTTP request: %s", err)
		return 0, 0, err
	}
	req.Header.Set("User-Agent", ua)
	if s.HwType == 1 {
		req.Host = s.HwUploadHeaders
	}

	if !s.Perception {
		req.Header.Set("Key", token)
	}

	uploadDone := make(chan struct{}, requests)

	doUpload := func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			log.Debugf("Failed when making HTTP request: %s", err)
		} else if err == nil {
			defer resp.Body.Close()
			if _, err := io.Copy(ioutil.Discard, resp.Body); err != nil {
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
