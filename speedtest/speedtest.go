package speedtest

import (
	"bytes"
	"context"
	"crypto/des"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gocarina/gocsv"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/ztelliot/taierspeed-cli/defs"
	"github.com/ztelliot/taierspeed-cli/report"
)

const (
	apiBaseUrl           = `https://dlc.cnspeedtest.com`
	apiPerceptionBaseUrl = `http://ux.caict.ac.cn`
)

//go:embed serverlist.json
var ServerListByte []byte

//go:embed province.csv
var ProvinceListByte []byte

type PingJob struct {
	Index  int
	Server defs.Server
}

type PingResult struct {
	Index int
	Ping  float64
}

func GetRandom(tp string) string {
	str := ""
	prefix := ""
	l := 0
	if tp == "DeviceID" {
		str = "0123456789abcdef"
		l = 16
	} else if tp == "IMEI" {
		str = "0123456789ABCDEF"
		prefix = "TS"
		l = 16
	} else {
		str = "0123456789"
		prefix = "taier"
		l = 6
	}
	bs := []byte(str)
	var res []byte
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < l; i++ {
		res = append(res, bs[r.Intn(len(bs))])
	}
	return prefix + string(res)
}

func Encrypt(src, key string) string {
	data := []byte(src)
	keyByte := []byte(key)
	block, err := des.NewCipher(keyByte)
	if err != nil {
		panic(err)
	}
	bs := block.BlockSize()
	data = PKCS5Padding(data, bs)
	if len(data)%bs != 0 {
		panic("Need a multiple of the blocksize")
	}
	out := make([]byte, len(data))
	dst := out
	for len(data) > 0 {
		block.Encrypt(dst, data[:bs])
		data = data[bs:]
		dst = dst[bs:]
	}
	return hex.EncodeToString(out)
}

func Decrypt(src, key string) []byte {
	data, err := hex.DecodeString(src)
	if err != nil {
		panic(err)
	}
	keyByte := []byte(key)
	block, err := des.NewCipher(keyByte)
	if err != nil {
		panic(err)
	}
	bs := block.BlockSize()
	if len(data)%bs != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	out := make([]byte, len(data))
	dst := out
	for len(data) > 0 {
		block.Decrypt(dst, data[:bs])
		data = data[bs:]
		dst = dst[bs:]
	}
	return PKCS5UnPadding(out)
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func Register() (string, error) {
	did := GetRandom("DeviceID")
	key := GetRandom("")
	pl := Encrypt(fmt.Sprintf("{\"deviceId\": \"%s\"}", did), key[:8])
	uri := fmt.Sprintf("%s/screen/taier/app/equipment/info?deviceId=%s&key=%s&json=%s", apiPerceptionBaseUrl, did, key, pl)

	req, err := http.NewRequest(http.MethodPost, uri, nil)
	if err != nil {
		log.Debugf("Failed when creating HTTP request: %s", err)
		return "", err
	}
	req.Header.Set("User-Agent", defs.UserAgentTS)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Debugf("Failed when making HTTP request: %s", err)
		return "", err
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Debugf("Failed when reading HTTP response: %s", err)
		return "", err
	}

	if len(b) <= 0 {
		return "", err
	}

	return did, nil
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
		if src != "" {
			// first we parse the IP to see if it's valid
			addr, err := net.ResolveIPAddr("ip", src)
			if err != nil {
				if strings.Contains(err.Error(), "no suitable address") {
					log.Errorf("Address %s is not a valid IP address", src)
				} else {
					log.Errorf("Error parsing source IP: %s", err)
				}
				return err
			}

			log.Debugf("Using %s as source IP", src)
			localTCPAddr = &net.TCPAddr{IP: addr.IP}
		}

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

	deviceId := ""
	var ispInfo *defs.IPInfoResponse
	// load server list
	var servers []defs.Server
	var err error
	var provinces []defs.ProvinceInfo
	var prov *defs.ProvinceInfo

	if err := gocsv.UnmarshalBytes(ProvinceListByte, &provinces); err != nil {
		log.Error("Failed to load province info")
		return err
	}

	if c.Bool(defs.OptionExperiment) {
		//deviceId, err = Register()
		//if err != nil {
		//	log.Errorf("Registry failed")
		//	return err
		//}

		deviceId = defs.DeviceID

		ispInfo, _ = getIPInfo()

		if ispInfo != nil {
			if ispInfo.Country != "中国" {
				prov = getProvInfo(provinces, "上海")
			} else {
				prov = getProvInfo(provinces, ispInfo.Region)
			}
		}

		// fetch the server list JSON and parse it into the `servers` array
		log.Infof("Retrieving server list")

		servers, err = getServerList(deviceId, prov, c.IntSlice(defs.OptionExclude), c.IntSlice(defs.OptionServer), !c.Bool(defs.OptionList), true)

		if err != nil {
			log.Errorf("Error when fetching server list: %s", err)
			return err
		}
	} else {
		if c.Bool(defs.OptionList) || len(c.IntSlice(defs.OptionServer)) > 0 {
			// fetch the server list JSON and parse it into the `servers` array
			log.Infof("Parsing server list")

			var serversT []defs.ServerTmp

			if err := json.Unmarshal(ServerListByte, &serversT); err == nil {
				for _, s := range serversT {
					servers = append(servers, defs.Server{ID: s.ID, IP: s.IP, Port: s.Port, Name: s.Name, Province: s.Prov})
				}
				servers, err = preprocessServers(servers, c.IntSlice(defs.OptionExclude), c.IntSlice(defs.OptionServer), !c.Bool(defs.OptionList), false)
			}
			if err != nil {
				log.Errorf("Error when parsing server list: %s", err)
				return err
			}
		}

		if !c.Bool(defs.OptionList) {
			ispInfo, _ = getIPInfo()
		}
	}

	// if --list is given, list all the servers fetched and exit
	if c.Bool(defs.OptionList) {
		for _, svr := range servers {
			fmt.Printf("%d: %s (%s)\n", svr.ID, svr.Name, svr.IP)
		}
		return nil
	}

	// if --server is given, do speed tests with all of them
	if len(c.IntSlice(defs.OptionServer)) > 0 {
		return doSpeedTest(c, servers, silent, ispInfo)
	} else {
		if c.Bool(defs.OptionExperiment) {
			// else select the fastest server from the list
			log.Info("Selecting the fastest server based on ping")

			var wg sync.WaitGroup
			jobs := make(chan PingJob, len(servers))
			results := make(chan PingResult, len(servers))
			done := make(chan struct{})

			pingList := make(map[int]float64)

			// spawn 10 concurrent pingers
			for i := 0; i < 10; i++ {
				go pingWorker(jobs, results, &wg, c.String(defs.OptionSource), c.Bool(defs.OptionNoICMP))
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
			for idx, ping := range pingList {
				if ping > 0 && ping <= pingList[serverIdx] {
					serverIdx = idx
				}
			}

			// do speed test on the server
			return doSpeedTest(c, []defs.Server{servers[serverIdx]}, silent, ispInfo)
		} else {
			if ispInfo != nil {
				servers, err = getOneServer(ispInfo.IP)
				return doSpeedTest(c, servers, silent, ispInfo)
			} else {
				log.Fatal("Get IP info failed")
				return nil
			}
		}
	}
}

func pingWorker(jobs <-chan PingJob, results chan<- PingResult, wg *sync.WaitGroup, srcIp string, noICMP bool) {
	for {
		job := <-jobs
		server := job.Server

		// check the server is up by accessing the ping URL and checking its returned value == empty and status code == 200
		if server.IsUp() {
			// skip ICMP if option given
			server.NoICMP = noICMP

			// if server is up, get ping
			ping, _, err := server.ICMPPingAndJitter(1, srcIp)
			if err != nil {
				log.Debugf("Can't ping server %s (%s), skipping", server.Name, server.IP)
				wg.Done()
				return
			}
			// return result
			results <- PingResult{Index: job.Index, Ping: ping}
			wg.Done()
		} else {
			log.Debugf("Server %s (%s) doesn't seem to be up, skipping", server.Name, server.IP)
			wg.Done()
		}
	}
}

// getServerList fetches the server JSON from a remote server
func getServerList(deviceId string, prov *defs.ProvinceInfo, excludes, specific []int, filter bool, perception bool) ([]defs.Server, error) {
	// --exclude and --server cannot be used at the same time
	if len(excludes) > 0 && len(specific) > 0 {
		return nil, errors.New("either --exclude or --server can be used")
	}

	// getting the server list from remote
	var servers []defs.Server
	old := false

	uri := ""
	if prov != nil {
		uri = fmt.Sprintf("%s/screen/taier/app/getSpeedServiceByUserId?deviceId=%s&lon=%s&lat=%s&userId=-10000&province=%s&operatorId=-1", apiPerceptionBaseUrl, deviceId, prov.Lon, prov.Lat, prov.Name)
	} else {
		uri = fmt.Sprintf("%s/screen/taier/ftp/encrypt/information?deviceId=%s", apiPerceptionBaseUrl, deviceId)
		old = true
	}
	req, err := http.NewRequest(http.MethodGet, uri, nil)
	q := req.URL.Query()
	req.URL.RawQuery = q.Encode()
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", defs.UserAgentTS)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if old {
		var resO map[string]json.RawMessage
		var data []string
		if err := json.Unmarshal(b, &resO); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(resO["data"], &data); err != nil {
			return nil, err
		}
		if string(resO["code"]) == "\"200\"" && len(data) == 2 {
			var res map[string]json.RawMessage
			key := data[0]
			data := data[1]
			if err := json.Unmarshal(Decrypt(data, key[:8]), &res); err != nil {
				return nil, err
			}
			if err := json.Unmarshal(res["ftplist"], &servers); err != nil {
				return nil, err
			}
		} else {
			return nil, errors.New(string(resO["message"]))
		}
	} else {
		var res map[string]json.RawMessage
		if err := json.Unmarshal(b, &res); err != nil {
			return nil, err
		}
		if string(res["code"]) == "\"200\"" {
			if err := json.Unmarshal(res["data"], &servers); err != nil {
				return nil, err
			}
		} else {
			return nil, errors.New(string(res["msg"]))
		}
	}

	return preprocessServers(servers, excludes, specific, filter, perception)
}

func getOneServer(ip string) ([]defs.Server, error) {
	uri := fmt.Sprintf("%s/dataServer/mobilematch.php?ip=%s&network=4", apiBaseUrl, ip)
	req, err := http.NewRequest(http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", defs.UserAgentTS)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var s defs.ServerTmp
	if err := json.Unmarshal(b, &s); err == nil {
		return []defs.Server{{ID: s.ID, IP: s.IP, Port: s.Port, Name: s.Name, Province: s.Prov}}, nil
	} else {
		return nil, err
	}
}

// preprocessServers makes some needed modifications to the servers fetched
func preprocessServers(servers []defs.Server, excludes, specific []int, filter bool, perception bool) ([]defs.Server, error) {
	if len(excludes) > 0 && len(specific) > 0 {
		return nil, errors.New("either --exclude or --specific can be used")
	}

	if filter {
		// exclude servers from --exclude
		if len(excludes) > 0 {
			var ret []defs.Server
			for _, server := range servers {
				if contains(excludes, server.ID) {
					continue
				}
				server.Perception = perception
				ret = append(ret, server)
			}
			return ret, nil
		}

		// use only servers from --server
		// special value -1 will test all servers
		if len(specific) > 0 && !contains(specific, -1) {
			var ret []defs.Server
			for _, server := range servers {
				if contains(specific, server.ID) {
					server.Perception = perception
					ret = append(ret, server)
				}
			}
			if len(ret) == 0 {
				error_message := fmt.Sprintf("specified server(s) not found: %v", specific)
				return nil, errors.New(error_message)
			}
			return ret, nil
		}

		if perception {
			var ret []defs.Server
			for _, server := range servers {
				server.Perception = perception
				ret = append(ret, server)
			}
			return ret, nil
		}
	}

	return servers, nil
}

func getProvInfo(provinces []defs.ProvinceInfo, name string) *defs.ProvinceInfo {
	var prov defs.ProvinceInfo

	if name == "" {
		return nil
	}

	for _, p := range provinces {
		if p.Short == name || strings.Contains(p.Name, name) || strings.Contains(name, p.Short) {
			prov = p
			break
		}
	}

	return &prov
}

func getIPInfo() (*defs.IPInfoResponse, error) {
	var ipInfo defs.IPInfoResponse
	var ispRaw []string

	uri := fmt.Sprintf("%s/dataServer/getIpLocS.php", apiBaseUrl)
	req, err := http.NewRequest(http.MethodGet, uri, nil)
	if err != nil {
		log.Debugf("Failed when creating HTTP request: %s", err)
		return nil, err
	}
	req.Header.Set("User-Agent", defs.UserAgentTS)

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
			ipInfo.District = ispRaw[3]
			ipInfo.Isp = ispRaw[4]
		}
	}

	return &ipInfo, nil
}

// contains is a helper function to check if an int is in an int array
func contains(arr []int, val int) bool {
	for _, v := range arr {
		if v == val {
			return true
		}
	}
	return false
}
