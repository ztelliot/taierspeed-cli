package defs

import (
	"encoding/json"
	"errors"
	"fmt"
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

func meiTuan(ip string) (*IPInfoResponse, error) {
	var mt struct {
		Data map[string]struct {
			Country  string `json:"nation"`
			Province string `json:"province"`
			City     string `json:"city"`
			ISP      string `json:"isp"`
		} `json:"data"`
	}

	if err := request(fmt.Sprintf("https://webapi-pc.meitu.com/common/ip_location?ip=%s", ip), &mt); err != nil {
		return nil, err
	} else {
		for k, v := range mt.Data {
			return &IPInfoResponse{
				IP:       k,
				Country:  v.Country,
				Province: v.Province,
				City:     v.City,
				ISP:      v.ISP,
			}, nil
		}
	}

	return nil, errors.New("no data")
}

func biliBiliLiveNew(ip string) (*IPInfoResponse, error) {
	var bili struct {
		Data IPInfoResponse `json:"data"`
	}

	if err := request(fmt.Sprintf("https://api.live.bilibili.com/client/v1/Ip/getInfoNew?ip=%s", ip), &bili); err != nil {
		return nil, err
	} else {
		return &bili.Data, nil
	}
}

func biliBiliLive(ip string) (*IPInfoResponse, error) {
	var bili struct {
		Data IPInfoResponse `json:"data"`
	}

	if err := request(fmt.Sprintf("https://api.live.bilibili.com/ip_service/v1/ip_service/get_ip_addr?ip=%s", ip), &bili); err != nil {
		return nil, err
	} else {
		return &bili.Data, nil
	}
}

func speedtestCN(ip string) (*IPInfoResponse, error) {
	var st struct {
		Data IPInfoResponse `json:"data"`
	}

	if err := request(fmt.Sprintf("https://api-v3-ipv6.speedtest.cn/ip?ip=%s", ip), &st); err != nil {
		return nil, err
	} else {
		return &st.Data, nil
	}
}

func GetIPInfo(ip string) (*IPInfoResponse, error) {
	var ipInfo *IPInfoResponse
	var err error

	for _, f := range []func(ip string) (*IPInfoResponse, error){meiTuan, biliBiliLiveNew, biliBiliLive, speedtestCN} {
		if ipInfo, err = f(ip); err == nil && ipInfo.IP != "" {
			return ipInfo, nil
		}
	}

	return nil, err
}
