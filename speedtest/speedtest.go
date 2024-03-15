package speedtest

import (
	"context"
	"crypto/des"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
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
	apiBaseUrl           = `https://dlc.cnspeedtest.com:8043`
	apiPerceptionBaseUrl = `https://ux.caict.ac.cn`
)

var DomainRe = regexp.MustCompile(`([a-zA-Z0-9][-a-zA-Z0-9]{0,62}\.)+([a-zA-Z][-a-zA-Z]{0,62})`)

//go:embed serverlist.json
var ServerListByte []byte

//go:embed province.csv
var ProvinceListByte []byte

//go:embed gdserverlist.json
var GDServerListByte []byte

type PingJob struct {
	Index  int
	Server defs.Server
}

type PingResult struct {
	Index int
	Ping  float64
}

func GetRandom(tok, pre string, l int) string {
	if tok == "" {
		tok = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	}
	bs := []byte(tok)
	var res []byte
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < l; i++ {
		res = append(res, bs[r.Intn(len(bs))])
	}
	return pre + string(res)
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

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
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

	if c.String(defs.OptionServerGroup) != "" && (len(c.StringSlice(defs.OptionProvince)) > 0 || len(c.StringSlice(defs.OptionISP)) > 0) {
		return fmt.Errorf("incompatible options '%s' and '%s' or '%s'", defs.OptionServerGroup, defs.OptionProvince, defs.OptionISP)
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

	var serverGroup []string
	if c.String(defs.OptionServerGroup) != "" {
		serverGroup = strings.Split(c.String(defs.OptionServerGroup), "@")
		if len(serverGroup) != 2 || serverGroup[0] == "" || serverGroup[1] == "" {
			log.Error("invalid server group")
			return errors.New("invalid server group")
		}
	}

	// HTTP requests timeout
	http.DefaultClient.Timeout = time.Duration(c.Int(defs.OptionTimeout)) * time.Second

	forceIPv4 := c.Bool(defs.OptionIPv4)
	forceIPv6 := c.Bool(defs.OptionIPv6)
	noICMP := c.Bool(defs.OptionNoICMP)

	// TODO: change transport here

	var ispInfo *defs.IPInfoResponse
	// load server list
	var servers []defs.Server
	var err error
	var provinces []defs.ProvinceInfo
	var provs []defs.ProvinceInfo
	var isps []*defs.ISPInfo

	if err := gocsv.UnmarshalBytes(ProvinceListByte, &provinces); err != nil {
		log.Error("Failed to load province info")
		return err
	}

	if !c.Bool(defs.OptionList) {
		ispInfo, _ = getIPInfo()
	}

	// TODO: refactor province filter

	isCN := false
	if len(c.StringSlice(defs.OptionProvince)) > 0 || len(serverGroup) > 0 {
		op := c.StringSlice(defs.OptionProvince)
		if len(op) <= 0 {
			op = []string{serverGroup[0]}
		}
		for _, p := range provinces {
			if contains(op, p.ID) || contains(op, p.Code) {
				provs = append(provs, p)
			}
		}
		if len(provs) == 0 {
			err = errors.New("specified province(s) not found")
			log.Errorf("Error when parsing server list: %s", err)
			return err
		}
	} else if !c.Bool(defs.OptionList) && len(c.StringSlice(defs.OptionServer)) <= 0 {
		if ispInfo != nil && ispInfo.Country == "中国" {
			isCN = true
			provs = append(provs, *getProvInfo(&provinces, ispInfo.Region))
		} else {
			provs = append(provs, *getProvInfo(&provinces, ""))
		}
	}

	if len(c.StringSlice(defs.OptionISP)) > 0 || len(serverGroup) > 0 {
		isCN = false
		oi := c.StringSlice(defs.OptionISP)
		if len(oi) <= 0 {
			oi = []string{serverGroup[1]}
		}
		for _, i := range defs.ISPList {
			if contains(oi, i.ID) || contains(oi, i.Short) {
				isps = append(isps, i)
			}
		}
		if len(isps) == 0 {
			err = errors.New("specified isp(s) not found")
			log.Errorf("Error when parsing server list: %s", err)
			return err
		}
	}

	hasGlobal, hasPerception, hasWireless := false, false, false
	if len(c.StringSlice(defs.OptionServer)) > 0 {
		for _, s := range c.StringSlice(defs.OptionServer) {
			if strings.HasPrefix(s, "P") {
				hasPerception = true
			} else if strings.HasPrefix(s, "W") {
				hasWireless = true
			} else {
				hasGlobal = true
			}
		}
	} else {
		hasGlobal, hasPerception, hasWireless = true, true, true
	}

	// fetch the server list JSON and parse it into the `servers` array
	log.Infof("Retrieving server list")

	if !c.Bool(defs.OptionDisableTai) && !forceIPv6 && hasGlobal {
		var serversT []defs.Server

		if serversT, err = getGlobalServerList(isCN, ispInfo, isps, &provs, &provinces); err != nil {
			log.Errorf("Error when fetching server list: %s", err)
			return err
		}
		if serversT, err = preprocessServers(serversT, c.StringSlice(defs.OptionExclude), c.StringSlice(defs.OptionServer), !c.Bool(defs.OptionList)); err != nil {
			log.Errorf("Error when preprocessing server list: %s", err)
			return err
		}
		servers = append(servers, serversT...)
	}

	if !c.Bool(defs.OptionDisablePet) && !(isCN && len(servers) > 0) && hasPerception {
		var serversP []defs.Server
		var serversPT []defs.Server

		if len(provs) <= 0 {
			serversP, err = getPerceptionServerList(nil, isps, &provinces)
		} else {
			for _, s := range provs {
				serversPT, err = getPerceptionServerList(&s, isps, &provinces)
				serversP = append(serversP, serversPT...)
			}
		}
		if err != nil {
			log.Errorf("Error when fetching server list: %s", err)
			return err
		}
		if serversP, err = preprocessServers(serversP, c.StringSlice(defs.OptionExclude), c.StringSlice(defs.OptionServer), !c.Bool(defs.OptionList)); err != nil {
			log.Errorf("Error when preprocessing server list: %s", err)
			return err
		}
		servers = append(servers, serversP...)
	}

	if !c.Bool(defs.OptionDisableWir) && !(isCN && len(servers) > 0) && hasWireless {
		if len(provs) <= 0 || checkProv(provs, &defs.GUANGDONG) {
			var serversW []defs.Server
			var serversWT []defs.ServerWireless

			if err = json.Unmarshal(GDServerListByte, &serversWT); err == nil {
				for _, s := range serversWT {
					isp := s.GetISP()
					if len(isps) <= 0 || checkISP(isps, isp) {
						serversW = append(serversW, defs.Server{ID: s.ID, Name: s.Name, IP: s.IP, IPv6: s.IPv6, URL: s.URL, URLv6: s.URLv6, Province: &defs.GUANGDONG, City: s.City, ISP: isp, Type: defs.WirelessSpeed})
					}
				}
			} else {
				log.Errorf("Error when fetching server list: %s", err)
				return err
			}

			if serversW, err = preprocessServers(serversW, c.StringSlice(defs.OptionExclude), c.StringSlice(defs.OptionServer), !c.Bool(defs.OptionList)); err != nil {
				log.Errorf("Error when preprocessing server list: %s", err)
				return err
			}
			servers = append(servers, serversW...)
		}
	}

	if forceIPv4 || forceIPv6 {
		var serversFiltered []defs.Server
		for _, server := range servers {
			if forceIPv4 && server.IP != "" {
				serversFiltered = append(serversFiltered, server)
			}
			if forceIPv6 && server.IPv6 != "" {
				serversFiltered = append(serversFiltered, server)
			}
		}
		servers = serversFiltered
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
			fmt.Printf("%s: %s (%s%s) %v\n", svr.GetID(), svr.Name, svr.Province.Short, svr.ISP.Name, stacks)
		}
		return nil
	}

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

	// if --server is given, do speed tests with all of them
	if len(c.StringSlice(defs.OptionServer)) > 0 || len(servers) == 1 {
		return doSpeedTest(c, servers, network, silent, noICMP, ispInfo)
	} else {
		// else select the fastest server from the list
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
		for idx, ping := range pingList {
			if ping > 0 && ping <= pingList[serverIdx] {
				serverIdx = idx
			}
		}

		// do speed test on the server
		return doSpeedTest(c, []defs.Server{servers[serverIdx]}, network, silent, noICMP, ispInfo)
	}
}

func pingWorker(jobs <-chan PingJob, results chan<- PingResult, wg *sync.WaitGroup, srcIp, network string, noICMP bool) {
	for {
		job := <-jobs
		server := job.Server

		// check the server is up by accessing the ping URL and checking its returned value == empty and status code == 200
		if server.IsUp(network) {
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
			log.Debugf("Server %s (%s) doesn't seem to be up, skipping", server.Name, server.IP)
			wg.Done()
		}
	}
}

// getPerceptionServerList fetches the server JSON from perception
func getPerceptionServerList(prov *defs.ProvinceInfo, isps []*defs.ISPInfo, provinces *[]defs.ProvinceInfo) ([]defs.Server, error) {
	// getting the server list from remote
	var servers []defs.ServerPerception
	var uri string
	old := false

	if prov != nil {
		uri = fmt.Sprintf("%s/screen/taier/app/getSpeedServiceByUserId?deviceId=%s&lon=%s&lat=%s&userId=-10000&province=%s&operatorId=-1", apiPerceptionBaseUrl, defs.DeviceID, prov.Lon, prov.Lat, prov.Name)
	} else {
		uri = fmt.Sprintf("%s/screen/taier/ftp/encrypt/information?deviceId=%s", apiPerceptionBaseUrl, defs.DeviceID)
		old = true
	}
	req, err := http.NewRequest(http.MethodGet, uri, nil)
	req.URL.RawQuery = req.URL.Query().Encode()
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

	var serversResolved []defs.Server
	for _, s := range servers {
		if s.Type == 1 || s.HwType == 1 {
			continue
		}
		server := defs.Server{ID: s.ID, Name: s.Name, IP: s.IP, DownloadURL: s.DownloadURL, UploadURL: s.UploadURL, PingURL: s.PingURL, Province: defs.MatchProvince(s.Prov, provinces), City: s.City, ISP: s.GetISP(), Type: defs.Perception}
		if downloadUrl, err := url.Parse(s.DownloadURL); err == nil {
			host := downloadUrl.Hostname()
			server.URL = host
			if DomainRe.MatchString(host) {
				if records, err := net.LookupHost(host); err == nil {
					for _, i := range records {
						if strings.Contains(i, ":") {
							server.IPv6 = i
						} else {
							server.IP = i
						}
					}
				}
			}
		}
		serversResolved = append(serversResolved, server)
	}

	var serversFiltered []defs.Server
	if prov != nil || len(isps) > 0 {
		for _, s := range serversResolved {
			if (prov != nil && prov.ID == s.Province.ID && (len(isps) <= 0 || checkISP(isps, s.ISP))) || (len(isps) > 0 && checkISP(isps, s.ISP) && (prov == nil || prov.ID == s.Province.ID)) {
				serversFiltered = append(serversFiltered, s)
			}
		}
		return serversFiltered, nil
	}

	return serversResolved, nil
}

func getGlobalServerList(isCN bool, isp *defs.IPInfoResponse, isps []*defs.ISPInfo, provs, provinces *[]defs.ProvinceInfo) ([]defs.Server, error) {
	var servers []defs.ServerGlobal

	if !isCN || isp == nil {
		if err := json.Unmarshal(ServerListByte, &servers); err != nil {
			return nil, err
		}
	} else {
		uri := fmt.Sprintf("%s/dataServer/mobilematch_list.php?ip=%s&network=4&ipv6=0", apiBaseUrl, isp.IP)
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

		if err = json.Unmarshal(b, &servers); err != nil {
			return nil, err
		}
	}

	var serversResolved []defs.Server

	for _, s := range servers {
		isp := s.GetISP()
		prov := s.GetProvince(provinces)
		if (provs == nil || len(*provs) <= 0 || checkProv(*provs, prov)) && (len(isps) <= 0 || checkISP(isps, isp)) {
			url := fmt.Sprintf("http://%s:%s/speed/", s.IP, s.Port)
			serversResolved = append(serversResolved, defs.Server{ID: s.ID, IP: s.IP, URL: url, Name: s.Name, Province: s.GetProvince(provinces), City: s.City, ISP: isp})
		}
	}
	return serversResolved, nil
}

// preprocessServers makes some needed modifications to the servers fetched
func preprocessServers(servers []defs.Server, excludes, specific []string, filter bool) ([]defs.Server, error) {
	if len(excludes) > 0 && len(specific) > 0 {
		return nil, errors.New("either --exclude or --specific can be used")
	}

	if filter {
		// exclude servers from --exclude
		if len(excludes) > 0 {
			var ret []defs.Server
			for _, server := range servers {
				if contains(excludes, server.GetID()) {
					continue
				}
				ret = append(ret, server)
			}
			return ret, nil
		}

		// use only servers from --server
		// special value -1 will test all servers
		if len(specific) > 0 && !contains(specific, "-1") {
			var ret []defs.Server
			for _, server := range servers {
				if contains(specific, server.GetID()) {
					ret = append(ret, server)
				}
			}
			return ret, nil
		}
	}

	return servers, nil
}

func getProvInfo(provinces *[]defs.ProvinceInfo, name string) *defs.ProvinceInfo {
	var prov *defs.ProvinceInfo

	if name != "" {
		prov = defs.MatchProvince(name, provinces)
	}

	if prov.ID != "" {
		return prov
	} else {
		return &defs.GUANGDONG
	}
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
	req.Header.Set("User-Agent", defs.AndroidUA)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Debugf("Failed when making HTTP request: %s", err)
		return nil, err
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
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

// contains is a helper function to check if a string is in a string array
func contains(arr []string, val string) bool {
	for _, v := range arr {
		if v == val {
			return true
		}
	}
	return false
}

func checkProv(arr []defs.ProvinceInfo, val *defs.ProvinceInfo) bool {
	for _, v := range arr {
		if v.ID == val.ID {
			return true
		}
	}
	return false
}

func checkISP(arr []*defs.ISPInfo, val *defs.ISPInfo) bool {
	for _, v := range arr {
		if v.ID == val.ID {
			return true
		}
	}
	return false
}
