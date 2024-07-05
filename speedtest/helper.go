package speedtest

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	"github.com/gocarina/gocsv"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/ztelliot/taierspeed-cli/defs"
	"github.com/ztelliot/taierspeed-cli/report"
)

func getRandom() string {
	bs := []byte("0123456789ABCDEF")
	var res []byte
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < 16; i++ {
		res = append(res, bs[r.Intn(len(bs))])
	}
	return "TS" + string(res)
}

func codeToCode(provider, code string) string {
	switch provider {
	case "azure":
		switch code {
		case "East Asia":
			return "HKG"
		}
	case "aws":
		switch code {
		case "ap-east-1":
			return "HKG"
		case "ap-southeast-1":
			return "SIN"
		case "ap-northeast-1":
			return "NRT"
		case "ap-northeast-2":
			return "ICN"
		case "ap-northeast-3":
			return "KIX"
		}
	case "gcp":
		switch code {
		case "asia-northeast1":
			return "NRT"
		case "asia-southeast1":
			return "SIN"
		}
	}
	return code
}

func coreApiDebug(resp *http.Response) {
	server := resp.Header.Get("X-Homo-Server")
	placement := resp.Header.Get("X-Homo-Region")
	var location string
	switch server {
	case "cloudflare":
		server = "Cloudflare"
		if lo := strings.Split(resp.Header.Get("Cf-Placement"), "-"); len(lo) > 0 {
			placement = lo[len(lo)-1]
		}
		if lo := strings.Split(resp.Header.Get("Cf-Ray"), "-"); len(lo) > 0 {
			location = lo[len(lo)-1]
		}
	case "azure":
		server = "Azure"
		placement = codeToCode("azure", placement)
		location = "HKG"
	case "deno":
		server = "Deno"
		placement = codeToCode("gcp", placement)
		if lo := strings.Split(resp.Header.Get("Server"), "/"); len(lo) > 0 {
			location = lo[len(lo)-1]
			if strings.HasPrefix(location, "gcp-") {
				location = codeToCode("gcp", strings.TrimPrefix(location, "gcp-"))
			}
		}
	case "deta":
		server = "Deta"
		placement = codeToCode("aws", placement)
	}
	if server == "" {
		log.Debugf("Core API server: %s", resp.Header.Get("Server"))
	} else {
		if location != "" && location != placement {
			log.Debugf("Core API server: %s %s, Edge: [%s]", server, placement, location)
		} else {
			log.Debugf("Core API server: %s %s", server, placement)
		}
	}
}

func apiGet[T []defs.Server | []defs.ServerResponse | defs.Version](c *cli.Context, path string, query url.Values) (ret T, err error) {
	coreApi, err := url.Parse(c.String(defs.OptionAPIBase))
	if err != nil {
		return
	}
	u := coreApi.JoinPath(c.String(defs.OptionAPIVersion)).JoinPath(path)

	if query != nil {
		u.RawQuery = query.Encode()
	}

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", defs.ApiUA)

	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if log.GetLevel() == log.DebugLevel {
		coreApiDebug(resp)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	log.Debugf("Time taken to get server list: %s", time.Since(start))

	if resp.StatusCode != http.StatusOK {
		if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") {
			err = fmt.Errorf("%s: %s", resp.Status, b)
			return
		}
		err = fmt.Errorf("%s", resp.Status)
		return
	}

	var res struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data T      `json:"data"`
	}
	if err = json.Unmarshal(b, &res); err != nil {
		return
	} else if res.Code != 0 {
		err = fmt.Errorf("API error: %d", res.Code)
		return
	}
	if res.Msg != "" {
		log.Warnln(res.Msg)
	}

	return res.Data, nil
}

func getServerMatch(c *cli.Context, ispInfo *defs.IPInfoResponse, stack defs.Stack) ([]defs.Server, error) {
	v := url.Values{}
	if ispInfo != nil && ispInfo.ProvId != 0 {
		v.Add("province", strconv.Itoa(int(ispInfo.ProvId)))
	}
	if ispInfo != nil && ispInfo.ISPId != 0 {
		v.Add("isp", strconv.Itoa(int(ispInfo.ISPId)))
	}
	if ispInfo != nil && ispInfo.City != "" {
		v.Add("city", ispInfo.City)
	}
	if stack != defs.StackAll {
		v.Add("stack", strconv.Itoa(int(stack)))
	}

	return apiGet[[]defs.Server](c, "node/match", v)
}

func getServerList(c *cli.Context, servers *[]string, groups *[]string, stack defs.Stack) ([]defs.ServerResponse, error) {
	v := url.Values{}
	if servers != nil && len(*servers) > 0 {
		v.Add("server", strings.Join(*servers, ","))
	}
	if groups != nil && len(*groups) > 0 {
		v.Add("group", strings.Join(*groups, ","))
	}
	if stack != defs.StackAll {
		v.Add("stack", strconv.Itoa(int(stack)))
	}

	return apiGet[[]defs.ServerResponse](c, "node", v)
}

func getVersion(c *cli.Context) (defs.Version, error) {
	return apiGet[defs.Version](c, fmt.Sprintf("version/latest/%s_%s", runtime.GOOS, runtime.GOARCH), nil)
}

func enQueue(s defs.Server) string {
	time.Local, _ = time.LoadLocation("Asia/Chongqing")
	ts := strconv.Itoa(int(time.Now().Local().Unix()))
	imei := getRandom()

	md5Ctx := md5.New()
	md5Ctx.Write([]byte(fmt.Sprintf("model=Android&imei=%s&stime=%s", imei, ts)))
	token := hex.EncodeToString(md5Ctx.Sum(nil))

	uri := s.URL().JoinPath("/speed/dovalid")
	uri.RawQuery = fmt.Sprintf("key=&flag=true&bandwidth=200&model=Android&imei=%s&time=%s&token=%s", imei, ts, token)

	req, err := http.NewRequest(http.MethodGet, uri.String(), nil)
	if err != nil {
		log.Debugf("Failed when creating HTTP request: %s", err)
		return ""
	}
	req.Header.Set("User-Agent", defs.AndroidUA)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Debugf("Failed when making HTTP request: %s", err)
		return ""
	}
	defer resp.Body.Close()

	if b, err := io.ReadAll(resp.Body); err != nil {
		log.Debugf("Failed when reading HTTP response: %s", err)
		return ""
	} else if resp.StatusCode != http.StatusOK || len(b) <= 0 {
		log.Debugf("Failed with %d: %s", resp.StatusCode, b)
		return ""
	} else {
		return string(b)[2:]
	}
}

func deQueue(s defs.Server, key string) bool {
	uri := s.URL().JoinPath("/speed/dovalid")
	uri.RawQuery = fmt.Sprintf("key=%s", key)

	req, err := http.NewRequest(http.MethodPost, uri.String(), nil)
	if err != nil {
		log.Debugf("Failed when creating HTTP request: %s", err)
		return false
	}
	req.Header.Set("Charset", "utf-8")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", defs.AndroidUA)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Debugf("Failed when making HTTP request: %s", err)
		return false
	}
	defer resp.Body.Close()

	if b, err := io.ReadAll(resp.Body); err != nil {
		log.Debugf("Failed when reading HTTP response: %s", err)
		return false
	} else if resp.StatusCode != http.StatusOK || len(b) <= 0 {
		log.Debugf("Failed with %d: %s", resp.StatusCode, b)
		return false
	}

	return true
}

func resolveHost(network, host string) string {
	r := &net.Resolver{PreferGo: true}
	if records, err := r.LookupIP(context.Background(), network, host); err == nil && len(records) > 0 {
		return records[0].String()
	}
	return ""
}

func MatchProvince(prov string, provinceMap *map[uint8]defs.ProvinceInfo) uint8 {
	for _, p := range *provinceMap {
		if p.ID == 0 {
			continue
		}
		if p.Short == prov || p.Name == prov || strings.Contains(p.Name, prov) || strings.Contains(prov, p.Short) {
			return p.ID
		}
	}
	return 0
}

func MatchISP(isp string) uint8 {
	for _, i := range defs.ISPMap {
		if i.ID == 0 {
			continue
		}
		if i.Name == isp || strings.Contains(isp, i.Name) || strings.Contains(i.Name, isp) {
			return i.ID
		}
	}
	return 0
}

// doSpeedTest is where the actual speed test happens
func doSpeedTest(c *cli.Context, servers []defs.Server, network string, silent, noICMP bool, ispInfo *defs.IPInfoResponse) error {
	if !silent || c.Bool(defs.OptionSimple) {
		if serverCount := len(servers); serverCount > 1 {
			fmt.Printf("Testing against %d servers: [ %s ]\n", serverCount, strings.Join(func() []string {
				var ret []string
				for _, s := range servers {
					ret = append(ret, s.Name)
				}
				return ret
			}(), ", "))
		} else if serverCount == 0 {
			fmt.Println("No server available")
			return nil
		}
		if ispInfo != nil {
			fmt.Println()
			if ispInfo.City == "" {
				if ispInfo.Province == "" {
					fmt.Printf("ISP:\t\t%s%s\n", ispInfo.Country, ispInfo.ISP)
				} else {
					fmt.Printf("ISP:\t\t%s%s\n", ispInfo.Province, ispInfo.ISP)
				}
			} else {
				fmt.Printf("ISP:\t\t%s%s\n", ispInfo.City, ispInfo.ISP)
			}
		}
		if len(servers) > 1 {
			fmt.Println()
		}
	}

	var repsOut []report.Result

	// fetch current user's IP info
	for _, currentServer := range servers {
		if !silent || c.Bool(defs.OptionSimple) {
			name := currentServer.Name
			if currentServer.Type == defs.Perception {
				name = fmt.Sprintf("%s - %s", currentServer.Name, defs.ISPMap[currentServer.ISP].Name)
			} else if currentServer.Type == defs.StaticFile {
				name = fmt.Sprintf("%s - %s%s", currentServer.Name, currentServer.Province, defs.ISPMap[currentServer.ISP].Name)
			}
			fmt.Printf("Server:\t\t%s [%s] (id = %s)\n", name, currentServer.Target, currentServer.ID)
		}

		if currentServer.IsUp() {
			// get ping and jitter value
			var pb *spinner.Spinner
			if !silent {
				pb = spinner.New(spinner.CharSets[11], 100*time.Millisecond)
				pb.Prefix = "Pinging...  "
				pb.Start()
			}

			// skip ICMP if option given
			currentServer.NoICMP = noICMP

			p, jitter, err := currentServer.ICMPPingAndJitter(c.Int(defs.OptionPingCount), c.String(defs.OptionSource), network)
			if err != nil {
				log.Errorf("Failed to get ping and jitter: %s", err)
				return err
			}

			if pb != nil {
				pb.FinalMSG = fmt.Sprintf("Latency:\t%.2f ms (%.2f ms jitter)\n", p, jitter)
				pb.Stop()
			} else if c.Bool(defs.OptionSimple) {
				fmt.Printf("Latency:\t%.2f ms (%.2f ms jitter)\n", p, jitter)
			}

			token := ""
			if currentServer.Type == defs.GlobalSpeed && !(c.Bool(defs.OptionNoDownload) && c.Bool(defs.OptionNoUpload)) {
				token = enQueue(currentServer)
				if len(token) <= 0 || token == "-" {
					log.Errorf("Get token failed")
					return nil
				}
			}

			// get download value
			var downloadValue float64
			var bytesRead uint64
			if c.Bool(defs.OptionNoDownload) {
				log.Info("Download test is disabled")
			} else {
				download, br, err := currentServer.Download(silent, c.Bool(defs.OptionBytes), c.Bool(defs.OptionMebiBytes), c.Int(defs.OptionConcurrent), time.Duration(c.Int(defs.OptionDuration))*time.Second, token)
				if err != nil {
					log.Errorf("Failed to get download speed: %s", err)
					return err
				}
				if c.Bool(defs.OptionSimple) {
					if c.Bool(defs.OptionBytes) {
						useMebi := c.Bool(defs.OptionMebiBytes)
						fmt.Printf("Download:\t%s (data used: %s)\n", humanizeMbps(download, useMebi), humanizeBytes(br, useMebi))
					} else {
						fmt.Printf("Download:\t%.2f Mbps (data used: %.2f MB)\n", download, float64(br)/1000000)
					}
				}
				downloadValue = download
				bytesRead = br
			}

			// get upload value
			var uploadValue float64
			var bytesWritten uint64
			if c.Bool(defs.OptionNoUpload) {
				log.Info("Upload test is disabled")
			} else if currentServer.Type == defs.StaticFile {
				log.Info("Upload test is not supported for this server")
			} else {
				upload, bw, err := currentServer.Upload(c.Bool(defs.OptionNoPreAllocate), silent, c.Bool(defs.OptionBytes), c.Bool(defs.OptionMebiBytes), c.Int(defs.OptionConcurrent), c.Int(defs.OptionUploadSize), time.Duration(c.Int(defs.OptionDuration))*time.Second, token)
				if err != nil {
					log.Errorf("Failed to get upload speed: %s", err)
					return err
				}
				if c.Bool(defs.OptionSimple) {
					if c.Bool(defs.OptionBytes) {
						useMebi := c.Bool(defs.OptionMebiBytes)
						fmt.Printf("Upload:\t\t%s (data used: %s)\n", humanizeMbps(upload, useMebi), humanizeBytes(bw, useMebi))
					} else {
						fmt.Printf("Upload:\t\t%.2f Mbps (data used: %.2f MB)\n", upload, float64(bw)/1000000)
					}
				}
				uploadValue = upload
				bytesWritten = bw
			}

			if currentServer.Type == defs.GlobalSpeed && !(c.Bool(defs.OptionNoDownload) && c.Bool(defs.OptionNoUpload)) {
				deQueue(currentServer, token)
			}

			// check for --csv or --json. the program prioritize the --csv before the --json. this is the same behavior as speedtest-cli
			if c.Bool(defs.OptionCSV) || c.Bool(defs.OptionJSON) {
				var rep report.Result
				rep.Timestamp = time.Now()

				rep.Ping = math.Round(p*100) / 100
				rep.Jitter = math.Round(jitter*100) / 100
				rep.Download = math.Round(downloadValue*100) / 100
				rep.Upload = math.Round(uploadValue*100) / 100
				rep.BytesReceived = bytesRead
				rep.BytesSent = bytesWritten

				rep.ID = currentServer.ID
				rep.IP = currentServer.Target
				rep.Name = currentServer.Name
				rep.Province = currentServer.Province
				rep.City = currentServer.City
				rep.ISP = defs.ISPMap[currentServer.ISP].Name

				repsOut = append(repsOut, rep)
			}
		} else {
			log.Infof("Selected server %s (%s) is not responding at the moment, try again later", currentServer.Name, currentServer.ID)
		}

		//add a new line after each test if testing multiple servers
		if len(servers) > 1 && (!silent || c.Bool(defs.OptionSimple)) {
			log.Warn()
		}
	}

	// check for --csv or --json. the program prioritize the --csv before the --json. this is the same behavior as speedtest-cli
	if c.Bool(defs.OptionCSV) {
		var buf bytes.Buffer
		if err := gocsv.MarshalWithoutHeaders(&repsOut, &buf); err != nil {
			log.Errorf("Error generating CSV report: %s", err)
		} else {
			os.Stdout.WriteString(buf.String())
		}
	} else if c.Bool(defs.OptionJSON) {
		jr := report.JSONReport{Results: repsOut}
		if ispInfo != nil {
			jr.Client = *ispInfo
		}
		if b, err := json.Marshal(&jr); err != nil {
			log.Errorf("Error generating JSON report: %s", err)
		} else {
			os.Stdout.Write(b[:])
		}
	}

	return nil
}

func humanizeMbps(mbps float64, useMebi bool) string {
	val := mbps / 8
	var base float64 = 1000
	if useMebi {
		base = 1024
	}

	if val < 1 {
		if kb := val * base; kb < 1 {
			return fmt.Sprintf("%.2f bytes/s", kb*base)
		} else {
			return fmt.Sprintf("%.2f KB/s", kb)
		}
	} else if val > base {
		return fmt.Sprintf("%.2f GB/s", val/base)
	} else {
		return fmt.Sprintf("%.2f MB/s", val)
	}
}

// humanizeBytes returns the Bytes/KiloBytes/MegaBytes/GigaBytes (or Bytes/KibiBytes/MebiBytes/GibiBytes)
func humanizeBytes(bytes uint64, useMebi bool) string {
	val := float64(bytes) / 8
	var base float64 = 1000
	if useMebi {
		base = 1024
	}

	if val < 1 {
		if kb := val * base; kb < 1 {
			return fmt.Sprintf("%.2f bytes", kb*base)
		} else {
			return fmt.Sprintf("%.2f KB", kb)
		}
	} else if val > base {
		return fmt.Sprintf("%.2f GB", val/base)
	} else {
		return fmt.Sprintf("%.2f MB", val)
	}
}
