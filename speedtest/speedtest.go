package speedtest

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gocarina/gocsv"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/ztelliot/taierspeed-cli/defs"
	"github.com/ztelliot/taierspeed-cli/report"
)

const (
	apiBaseUrl = `https://dlc.cnspeedtest.com`
)

//go:embed serverlist.json
var ServerListByte []byte

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

	// set CSV delimiter
	gocsv.TagSeparator = c.String(defs.OptionCSVDelimiter)

	// if --csv-header is given, print the header and exit (same behavior speedtest-cli)
	if c.Bool(defs.OptionCSVHeader) {
		var rep []report.CSVReport
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

	transport := http.DefaultTransport.(*http.Transport).Clone()

	// bind to source IP address if given
	if src := c.String(defs.OptionSource); src != "" {
		var localTCPAddr *net.TCPAddr

		var dialContext func(context.Context, string, string) (net.Conn, error)
		defaultDialer := &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}

		if localTCPAddr != nil {
			defaultDialer.LocalAddr = localTCPAddr
		}

		dialContext = defaultDialer.DialContext

		// set default HTTP client's Transport to the one that binds the source address
		// this is modified from http.DefaultTransport
		transport.DialContext = dialContext
	}

	http.DefaultClient.Transport = transport

	// load server list
	var servers []defs.Server
	var err error

	if c.Bool(defs.OptionList) || len(c.StringSlice(defs.OptionServer)) > 0 {
		// fetch the server list JSON and parse it into the `servers` array
		log.Infof("Parsing server list")

		if err := json.Unmarshal(ServerListByte, &servers); err == nil {
			servers, err = preprocessServers(servers, c.StringSlice(defs.OptionServer), !c.Bool(defs.OptionList))
		}
		if err != nil {
			log.Errorf("Error when parsing server list: %s", err)
			return err
		}

		// if --list is given, list all the servers fetched and exit
		if c.Bool(defs.OptionList) {
			for _, svr := range servers {
				fmt.Printf("%s: %s (%s)\n", svr.ID, svr.Name, svr.IP)
			}
			return nil
		}
	}

	ispInfo, _ := getIPInfo()

	// if --server is given, do speed tests with all of them
	if len(c.StringSlice(defs.OptionServer)) > 0 {
		return doSpeedTest(c, servers, silent, ispInfo)
	} else {
		servers, err = getOneServer(ispInfo.IP)
		return doSpeedTest(c, servers, silent, ispInfo)
	}
}

func getOneServer(ip string) ([]defs.Server, error) {
	var server defs.Server
	url := fmt.Sprintf("%s/dataServer/mobilematch.php?ip=%s&network=4", apiBaseUrl, ip)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", defs.UserAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := json.Unmarshal(b, &server); err != nil {
		return nil, err
	}

	return []defs.Server{server}, nil
}

// preprocessServers makes some needed modifications to the servers fetched
func preprocessServers(servers []defs.Server, specific []string, filter bool) ([]defs.Server, error) {
	if filter {
		// use only servers from --server
		// special value -1 will test all servers
		if len(specific) > 0 && !contains(specific, "-1") {
			var ret []defs.Server
			for _, server := range servers {
				if contains(specific, server.ID) {
					ret = append(ret, server)
				}
			}
			if len(ret) == 0 {
				error_message := fmt.Sprintf("specified server(s) not found: %v", specific)
				return nil, errors.New(error_message)
			}
			return ret, nil
		}
	}

	return servers, nil
}

func getIPInfo() (*defs.IPInfoResponse, error) {
	var ipInfo defs.IPInfoResponse
	var ispRaw []string

	url := fmt.Sprintf("%s/dataServer/getIpLocS.php", apiBaseUrl)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Debugf("Failed when creating HTTP request: %s", err)
		return nil, err
	}
	req.Header.Set("User-Agent", defs.UserAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Debugf("Failed when making HTTP request: %s", err)
		return nil, err
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Debugf("Failed when reading HTTP response: %s", err)
		return nil, err
	}

	if len(b) > 0 {
		data := strings.Split(string(b), "|")
		ipInfo.IP = data[0]
		if err := json.Unmarshal([]byte(data[1]), &ispRaw); err == nil {
			ipInfo.Country = ispRaw[0]
			ipInfo.Region = ispRaw[1]
			ipInfo.City = ispRaw[2]
			ipInfo.Area = ispRaw[3]
			ipInfo.Isp = ispRaw[4]
		}
	}

	return &ipInfo, nil
}

// contains is a helper function to check if an int is in an int array
func contains(arr []string, val string) bool {
	for _, v := range arr {
		if v == val {
			return true
		}
	}
	return false
}
