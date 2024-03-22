package speedtest

import (
	"context"
	"database/sql"
	"embed"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	_ "modernc.org/sqlite"
	"modernc.org/sqlite/vfs"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gocarina/gocsv"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/ztelliot/taierspeed-cli/defs"
	"github.com/ztelliot/taierspeed-cli/report"
)

var DomainRe = regexp.MustCompile(`([a-zA-Z0-9][-a-zA-Z0-9]{0,62}\.)+([a-zA-Z][-a-zA-Z]{0,62})`)

//go:embed speedtest.db
var SpeedDb embed.FS

type PingJob struct {
	Index  int
	Server defs.Server
}

type PingResult struct {
	Index int
	Ping  float64
}

// SpeedTest is the actual main function that handles the speed test(s)
func SpeedTest(c *cli.Context) error {
	// check for suppressed output flags
	var silent bool
	if c.Bool(defs.OptionSimple) || c.Bool(defs.OptionJSON) || c.Bool(defs.OptionCSV) {
		log.SetLevel(log.WarnLevel)
		silent = true
	}

	// check for debug flag
	if c.Bool(defs.OptionDebug) {
		log.SetLevel(log.DebugLevel)
	}

	// print help
	if c.Bool(defs.OptionHelp) {
		return cli.ShowAppHelp(c)
	}

	// print version
	if c.Bool(defs.OptionVersion) {
		log.SetOutput(os.Stdout)
		log.Warnf("%s %s (built on %s)", defs.ProgName, defs.ProgVersion, defs.BuildDate)
		log.Warn("Powered by TaierSpeed")
		log.Warn("Project: https://github.com/ztelliot/taierspeed-cli")
		log.Warn("Forked: https://github.com/librespeed/speedtest-cli")
		return nil
	}

	if c.String(defs.OptionSource) != "" && c.String(defs.OptionInterface) != "" {
		return fmt.Errorf("incompatible options '%s' and '%s'", defs.OptionSource, defs.OptionInterface)
	}

	// set CSV delimiter
	gocsv.TagSeparator = c.String(defs.OptionCSVDelimiter)

	// if --csv-header is given, print the header and exit (same behavior speedtest-cli)
	if c.Bool(defs.OptionCSVHeader) {
		var rep []report.Result
		b, _ := gocsv.MarshalBytes(&rep)
		os.Stdout.WriteString(string(b))
		return nil
	}

	if req := c.Int(defs.OptionConcurrent); req <= 0 {
		log.Errorf("Concurrent requests cannot be lower than 1: %d is given", req)
		return errors.New("invalid concurrent requests setting")
	}

	// HTTP requests timeout
	http.DefaultClient.Timeout = time.Duration(c.Int(defs.OptionTimeout)) * time.Second

	forceIPv4 := c.Bool(defs.OptionIPv4)
	forceIPv6 := c.Bool(defs.OptionIPv6)
	noICMP := c.Bool(defs.OptionNoICMP)

	var network string
	switch {
	case forceIPv4:
		network = "ip4"
	case forceIPv6:
		network = "ip6"
	default:
		network = "ip"
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()

	// bind to source IP address or interface if given, or if ipv4/ipv6 is forced
	if src, iface := c.String(defs.OptionSource), c.String(defs.OptionInterface); src != "" || iface != "" || forceIPv4 || forceIPv6 {
		var localTCPAddr *net.TCPAddr
		if src != "" {
			// first we parse the IP to see if it's valid
			addr, err := net.ResolveIPAddr(network, src)
			if err != nil {
				if strings.Contains(err.Error(), "no suitable address") {
					if forceIPv6 {
						log.Errorf("Address %s is not a valid IPv6 address", src)
					} else {
						log.Errorf("Address %s is not a valid IPv4 address", src)
					}
				} else {
					log.Errorf("Error parsing source IP: %s", err)
				}
				return err
			}

			log.Debugf("Using %s as source IP", src)
			localTCPAddr = &net.TCPAddr{IP: addr.IP}
		}

		var defaultDialer *net.Dialer
		var dialContext func(context.Context, string, string) (net.Conn, error)

		if iface != "" {
			defaultDialer = newInterfaceDialer(iface)
			noICMP = true
		} else {
			defaultDialer = &net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}
		}

		if localTCPAddr != nil {
			defaultDialer.LocalAddr = localTCPAddr
		}

		switch {
		case forceIPv4:
			dialContext = func(ctx context.Context, network, address string) (conn net.Conn, err error) {
				return defaultDialer.DialContext(ctx, "tcp4", address)
			}
		case forceIPv6:
			dialContext = func(ctx context.Context, network, address string) (conn net.Conn, err error) {
				return defaultDialer.DialContext(ctx, "tcp6", address)
			}
		default:
			dialContext = defaultDialer.DialContext
		}

		// set default HTTP client's Transport to the one that binds the source address
		// this is modified from http.DefaultTransport
		transport.DialContext = dialContext
	}

	http.DefaultClient.Transport = transport

	var ispInfo *defs.IPInfoResponse
	var servers []defs.Server
	var err error

	if !c.Bool(defs.OptionList) {
		ispInfo, _ = defs.GetIPInfo()
	}

	simple := true
	if forceIPv6 || c.Bool(defs.OptionList) || c.IsSet(defs.OptionServer) || c.IsSet(defs.OptionServerGroup) || ispInfo == nil || ispInfo.IP == "" {
		simple = false
	}

	// fetch the server list JSON and parse it into the `servers` array
	log.Infof("Retrieving server list")

	if simple {
		var serversT []defs.Server

		if serversT, err = getGlobalServerList(ispInfo.IP); err != nil {
			log.Errorf("Error when fetching server list: %s", err)
			return err
		}
		if serversT, err = preprocessServers(serversT, c.StringSlice(defs.OptionExclude), c.StringSlice(defs.OptionServer)); err != nil {
			log.Errorf("Error when preprocessing server list: %s", err)
			return err
		}
		if c.Bool(defs.OptionDebug) {
			debugServer(&serversT, "Fetched")
		}
		servers = append(servers, selectServer(serversT, network, c, noICMP))
	} else {
		var groups []defs.Group

		fn, f, err := vfs.New(SpeedDb)
		if err != nil {
			log.Error("Failed to load database")
			return err
		}
		defer f.Close()

		db, err := sql.Open("sqlite", "file:speedtest.db?vfs="+fn)
		if err != nil {
			log.Error("Failed to load database")
			return err
		}

		if c.IsSet(defs.OptionServerGroup) {
			for _, s := range c.StringSlice(defs.OptionServerGroup) {
				sg := strings.Split(s, "@")
				sgp, sgi := "", ""
				switch len(sg) {
				case 1:
					sgp = sg[0]
				case 2:
					sgp, sgi = sg[0], sg[1]
				default:
					continue
				}

				var isp uint8 = 0
				if sgi != "" {
					for _, i := range defs.ISPMap {
						if sgi == strconv.Itoa(int(i.ASN)) || sgi == i.Short {
							isp = i.ID
						}
					}
					if isp == 0 {
						continue
					}
				}

				groups = append(groups, defs.Group{Province: sgp, ISP: isp})
			}
		} else if forceIPv6 || c.Bool(defs.OptionList) || c.IsSet(defs.OptionServer) {
			groups = append(groups, defs.Group{Province: "", ISP: 0})
		} else {
			groups = append(groups, defs.Group{Province: "sh", ISP: 1})
		}

		for _, g := range groups {
			var serversT []defs.Server

			query := "SELECT servers.id, servers.name, host, port, city, isp, download, upload, ping, type, short FROM servers, provinces WHERE province == provinces.id"
			if g.Province != "" {
				query += fmt.Sprintf(" AND code == '%s'", g.Province)
			}
			if g.ISP != 0 {
				query += fmt.Sprintf(" AND isp == %d", g.ISP)
			}
			if row, err := db.Query(query); err == nil {
				for row.Next() {
					var s defs.Server
					if err := row.Scan(&s.ID, &s.Name, &s.Host, &s.Port, &s.City, &s.ISP, &s.DownloadURI, &s.UploadURI, &s.PingURI, &s.Type, &s.Province); err == nil {
						if DomainRe.MatchString(s.Host) {
							if records, err := net.LookupHost(s.Host); err == nil {
								for _, i := range records {
									if strings.Contains(i, ":") {
										s.IPv6 = i
									} else {
										s.IP = i
									}
								}
							}
						} else {
							if strings.Contains(s.Host, ":") {
								s.IPv6 = s.Host
							} else {
								s.IP = s.Host
							}
						}

						if forceIPv4 || forceIPv6 {
							if forceIPv4 && s.IP == "" {
								continue
							}
							if forceIPv6 && s.IPv6 == "" {
								continue
							}
						}
						serversT = append(serversT, s)
					}
				}
			}

			if serversT, err = preprocessServers(serversT, c.StringSlice(defs.OptionExclude), c.StringSlice(defs.OptionServer)); err != nil {
				log.Errorf("Error when preprocessing server list: %s", err)
				return err
			}
			if c.Bool(defs.OptionList) || c.IsSet(defs.OptionServer) {
				servers = append(servers, serversT...)
			} else {
				if c.Bool(defs.OptionDebug) {
					debugServer(&serversT, "Fetched")
				}
				servers = append(servers, selectServer(serversT, network, c, noICMP))
			}
		}
	}

	if c.Bool(defs.OptionDebug) && !c.Bool(defs.OptionList) {
		debugServer(&servers, "Selected")
	}
	if len(servers) == 0 {
		err = errors.New("specified server(s) not found")
	}

	if err != nil {
		log.Errorf("Error when parsing server list: %s", err)
		return err
	}

	// if --list is given, list all the servers fetched and exit
	if c.Bool(defs.OptionList) {
		for _, svr := range servers {
			var stacks []string
			if svr.IP != "" {
				stacks = append(stacks, "IPv4")
			}
			if svr.IPv6 != "" {
				stacks = append(stacks, "IPv6")
			}
			fmt.Printf("%s: %s (%s%s) %v\n", svr.ID, svr.Name, svr.Province, defs.ISPMap[svr.ISP].Name, stacks)
		}
		return nil
	}

	return doSpeedTest(c, servers, network, silent, noICMP, ispInfo)
}

func selectServer(servers []defs.Server, network string, c *cli.Context, noICMP bool) defs.Server {
	if len(servers) > 10 {
		r := rand.New(rand.NewSource(time.Now().Unix()))
		r.Shuffle(len(servers), func(i int, j int) {
			servers[i], servers[j] = servers[j], servers[i]
		})
		servers = servers[:10]
		if c.Bool(defs.OptionDebug) {
			debugServer(&servers, "Randomly choice")
		}
	}

	log.Info("Selecting the fastest server based on ping")

	var wg sync.WaitGroup
	jobs := make(chan PingJob, len(servers))
	results := make(chan PingResult, len(servers))
	done := make(chan struct{})

	pingList := make(map[int]float64)

	// spawn 10 concurrent pingers
	for i := 0; i < 10; i++ {
		go pingWorker(jobs, results, &wg, c.String(defs.OptionSource), network, noICMP)
	}

	// send ping jobs to workers
	for idx, server := range servers {
		wg.Add(1)
		jobs <- PingJob{Index: idx, Server: server}
	}

	go func() {
		wg.Wait()
		close(done)
	}()

Loop:
	for {
		select {
		case result := <-results:
			pingList[result.Index] = result.Ping
		case <-done:
			break Loop
		}
	}

	if len(pingList) == 0 {
		log.Fatal("No server is currently available, please try again later.")
	}

	// get the fastest server's index in the `servers` array
	var serverIdx int
	minPing := math.MaxFloat64
	for idx, ping := range pingList {
		if ping > 0 && ping <= minPing {
			serverIdx = idx
		}
	}

	// do speed test on the server
	return servers[serverIdx]
}

func pingWorker(jobs <-chan PingJob, results chan<- PingResult, wg *sync.WaitGroup, srcIp, network string, noICMP bool) {
	for {
		job := <-jobs
		server := job.Server

		// check the server is up by accessing the ping URL and checking its returned value == empty and status code == 200
		if server.IsUp() {
			// skip ICMP if option given
			server.NoICMP = noICMP

			// if server is up, get ping
			ping, _, err := server.ICMPPingAndJitter(1, srcIp, network)
			if err != nil {
				log.Debugf("Can't ping server %s (%s), skipping", server.Name, server.IP)
				wg.Done()
				return
			}
			// return result
			results <- PingResult{Index: job.Index, Ping: ping}
			wg.Done()
		} else {
			log.Debugf("Server %s (%s) seems down, skipping", server.Name, server.IP)
			wg.Done()
		}
	}
}

func getGlobalServerList(ip string) ([]defs.Server, error) {
	var serversT []defs.ServerGlobal

	uri := fmt.Sprintf("https://dlc.cnspeedtest.com:8043/dataServer/mobilematch_list.php?ip=%s&network=4&ipv6=0", ip)
	req, err := http.NewRequest(http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", defs.AndroidUA)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err = json.Unmarshal(b, &serversT); err != nil {
		return nil, err
	}

	var servers []defs.Server
	for _, s := range serversT {
		port, _ := strconv.Atoi(s.Port)
		servers = append(servers, defs.Server{ID: strconv.Itoa(s.ID), Name: s.Name, IP: s.IP, Host: s.IP, Port: uint16(port), Province: s.Prov, City: s.City, ISP: s.GetISP().ID})
	}
	return servers, nil
}

// preprocessServers makes some needed modifications to the servers fetched
func preprocessServers(servers []defs.Server, excludes, specific []string) ([]defs.Server, error) {
	// exclude servers from --exclude
	if len(excludes) > 0 && len(specific) == 0 {
		var ret []defs.Server
		for _, server := range servers {
			if contains(excludes, server.ID) {
				continue
			}
			ret = append(ret, server)
		}
		return ret, nil
	} else if len(excludes) == 0 && len(specific) > 0 {
		var ret []defs.Server
		for _, server := range servers {
			if contains(specific, server.ID) {
				ret = append(ret, server)
			}
		}
		return ret, nil
	} else if len(excludes) > 0 && len(specific) > 0 {
		var ret []defs.Server
		for _, server := range servers {
			if contains(specific, server.ID) && !contains(excludes, server.ID) {
				ret = append(ret, server)
			}
		}
		return ret, nil
	} else {
		return servers, nil
	}
}

// contains is a helper function to check if a string is in a string array
func contains(arr []string, val string) bool {
	for _, v := range arr {
		if v == val {
			return true
		}
	}
	return false
}
