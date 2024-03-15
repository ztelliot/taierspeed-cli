package speedtest

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/briandowns/spinner"
	"github.com/gocarina/gocsv"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/ztelliot/taierspeed-cli/defs"
	"github.com/ztelliot/taierspeed-cli/report"
)

const (
	// the default ping count for measuring ping and jitter
	pingCount = 5
)

func enQueue(s defs.Server) string {
	time.Local, _ = time.LoadLocation("Asia/Chongqing")
	ts := strconv.Itoa(int(time.Now().Local().Unix()))
	imei := GetRandom("0123456789ABCDEF", "TS", 16)

	md5Ctx := md5.New()
	md5Ctx.Write([]byte(fmt.Sprintf("model=Android&imei=%s&stime=%s", imei, ts)))
	token := hex.EncodeToString(md5Ctx.Sum(nil))

	url := fmt.Sprintf("%sdovalid?key=&flag=true&bandwidth=200&model=Android&imei=%s&time=%s&token=%s", s.URL, imei, ts, token)

	req, err := http.NewRequest(http.MethodGet, url, nil)
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

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Debugf("Failed when reading HTTP response: %s", err)
		return ""
	}

	if resp.StatusCode != http.StatusOK {
		log.Debugf("Failed with %d: %s", resp.StatusCode, b)
		return ""
	}

	if len(b) <= 0 {
		return ""
	}

	return string(b)[2:]
}

func deQueue(s defs.Server, key string) bool {
	url := fmt.Sprintf("%sspeed/dovalid?key=%s", s.URL, key)

	req, err := http.NewRequest(http.MethodPost, url, nil)
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

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Debugf("Failed when reading HTTP response: %s", err)
		return false
	}

	if len(b) <= 0 {
		return false
	}

	return true
}

// doSpeedTest is where the actual speed test happens
func doSpeedTest(c *cli.Context, servers []defs.Server, network string, silent, noICMP bool, ispInfo *defs.IPInfoResponse) error {
	if !silent || c.Bool(defs.OptionSimple) {
		if serverCount := len(servers); serverCount > 1 {
			fmt.Printf("Testing against %d servers\n", serverCount)
		} else if serverCount == 0 {
			fmt.Println("No server available")
			return nil
		}
		if ispInfo != nil {
			fmt.Printf("ISP:\t\t%s%s\n", ispInfo.City, ispInfo.Isp)
		} else {
			fmt.Printf("ISP:\n")
		}
		if len(servers) > 1 {
			fmt.Printf("\n")
		}
	}

	var repsOut []report.Result

	// fetch current user's IP info
	for _, currentServer := range servers {
		if !silent || c.Bool(defs.OptionSimple) {
			name, ip := currentServer.Name, currentServer.IP
			if currentServer.Type == defs.Perception {
				name = fmt.Sprintf("%s - %s", currentServer.Name, currentServer.ISP.Name)
			}
			if network == "ip6" {
				ip = currentServer.IPv6
			}
			fmt.Printf("Server:\t\t%s [%s] (id = %s)\n", name, ip, currentServer.GetID())
		}

		if currentServer.IsUp(network) {
			// get ping and jitter value
			var pb *spinner.Spinner
			if !silent {
				pb = spinner.New(spinner.CharSets[11], 100*time.Millisecond)
				pb.Prefix = "Pinging...  "
				pb.Start()
			}

			// skip ICMP if option given
			currentServer.NoICMP = noICMP

			p, jitter, err := currentServer.ICMPPingAndJitter(pingCount, c.String(defs.OptionSource), network)
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
				download, br, err := currentServer.Download(silent, c.Bool(defs.OptionBytes), c.Bool(defs.OptionMebiBytes), c.Int(defs.OptionConcurrent), time.Duration(c.Int(defs.OptionDuration))*time.Second, network, token)
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
			} else {
				upload, bw, err := currentServer.Upload(c.Bool(defs.OptionNoPreAllocate), silent, c.Bool(defs.OptionBytes), c.Bool(defs.OptionMebiBytes), c.Int(defs.OptionConcurrent), c.Int(defs.OptionUploadSize), time.Duration(c.Int(defs.OptionDuration))*time.Second, network, token)
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

				rep.ID = currentServer.GetID()
				switch network {
				case "ip6":
					rep.IP = currentServer.IPv6
				default:
					rep.IP = currentServer.IP
				}
				rep.Name = currentServer.Name
				rep.Province = currentServer.ProvinceInfo.Short
				rep.City = currentServer.City
				rep.ISP = currentServer.ISP.Name

				repsOut = append(repsOut, rep)
			}
		} else {
			log.Infof("Selected server %s (%s) is not responding at the moment, try again later", currentServer.Name, currentServer.GetID())
		}

		//add a new line after each test if testing multiple servers
		if len(servers) > 1 && !silent {
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
		if b, err := json.Marshal(&report.JSONReport{Client: *ispInfo, Results: repsOut}); err != nil {
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
