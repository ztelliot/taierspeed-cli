package defs

import (
	"encoding/json"
	"errors"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
)

type IPInfoResponse struct {
	IP       string `json:"addr"`
	Country  string `json:"country"`
	Province string `json:"province"`
	ProvId   uint8  `json:"-"`
	City     string `json:"city"`
	ISP      string `json:"isp"`
	ISPId    uint8  `json:"-"`
}

func request(url string, obj any) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Debugf("Failed when creating HTTP request: %s", err)
		return err
	}
	req.Header.Set("User-Agent", AndroidUA)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Debugf("Failed when making HTTP request: %s", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}

	if b, err := io.ReadAll(resp.Body); err != nil {
		log.Debugf("Failed when reading HTTP response: %s", err)
		return err
	} else {
		if err = json.Unmarshal(b, obj); err != nil {
			return err
		}
	}

	return nil
}

func uPai() (*IPInfoResponse, error) {
	var upaiyun struct {
		IP     string         `json:"remote_addr"`
		Detail IPInfoResponse `json:"remote_addr_location"`
	}

	if err := request("https://pubstatic.b0.upaiyun.com/?_upnode", &upaiyun); err != nil {
		return nil, err
	} else {
		upaiyun.Detail.IP = upaiyun.IP
		return &upaiyun.Detail, nil
	}
}

func bilibili() (*IPInfoResponse, error) {
	var bili struct {
		Data IPInfoResponse `json:"data"`
	}

	if err := request("https://api.bilibili.com/x/web-interface/zone", &bili); err != nil {
		return nil, err
	} else {
		return &bili.Data, nil
	}
}

func bilibiliLive() (*IPInfoResponse, error) {
	var bili struct {
		Data IPInfoResponse `json:"data"`
	}

	if err := request("https://api.live.bilibili.com/ip_service/v1/ip_service/get_ip_addr", &bili); err != nil {
		return nil, err
	} else {
		return &bili.Data, nil
	}
}

func ipip() (*IPInfoResponse, error) {
	var data struct {
		Data struct {
			IP       string   `json:"ip"`
			Location []string `json:"location"`
		} `json:"data"`
	}

	if err := request("http://myip6.ipip.net/json", &data); err != nil {
		return nil, err
	} else {
		var ipInfo IPInfoResponse
		ipInfo.IP = data.Data.IP
		ipInfo.Country = data.Data.Location[0]
		ipInfo.Province = data.Data.Location[1]
		ipInfo.City = data.Data.Location[2]
		ipInfo.ISP = data.Data.Location[4]
		return &ipInfo, nil
	}
}

func GetIPInfo() (*IPInfoResponse, error) {
	var ipInfo *IPInfoResponse
	var err error

	for _, f := range []func() (*IPInfoResponse, error){uPai, ipip, bilibiliLive, bilibili} {
		if ipInfo, err = f(); err == nil && ipInfo.IP != "" {
			return ipInfo, nil
		}
	}

	return nil, err
}
