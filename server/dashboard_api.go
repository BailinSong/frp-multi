// Copyright 2017 frp, frp@gmail.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"frp/utils/util"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"frp/g"
	"frp/models/config"
	"frp/models/consts"
	"frp/utils/log"
	"frp/utils/version"

	"github.com/gorilla/mux"
)

type GeneralResponse struct {
	Code int64  `json:"code"`
	Msg  string `json:"msg"`
}

type ServerInfoResp struct {
	GeneralResponse

	Version           string `json:"version"`
	BindPort          int    `json:"bind_port"`
	BindUdpPort       int    `json:"bind_udp_port"`
	VhostHttpPort     int    `json:"vhost_http_port"`
	VhostHttpsPort    int    `json:"vhost_https_port"`
	KcpBindPort       int    `json:"kcp_bind_port"`
	SubdomainHost     string `json:"subdomain_host"`
	MaxPoolCount      int64  `json:"max_pool_count"`
	MaxPortsPerClient int64  `json:"max_ports_per_client"`
	HeartBeatTimeout  int64  `json:"heart_beat_timeout"`

	TotalTrafficIn  int64            `json:"total_traffic_in"`
	TotalTrafficOut int64            `json:"total_traffic_out"`
	CurConns        int64            `json:"cur_conns"`
	ClientCounts    int64            `json:"client_counts"`
	ProxyTypeCounts map[string]int64 `json:"proxy_type_count"`
}

// api/serverinfo
func (svr *Service) ApiServerInfo(w http.ResponseWriter, r *http.Request) {
	var (
		buf []byte
		res ServerInfoResp
	)
	defer func() {
		log.Info("Http response [%s]: code [%d]", r.URL.Path, res.Code)
	}()

	log.Info("Http request: [%s]", r.URL.Path)
	cfg := &g.GlbServerCfg.ServerCommonConf
	serverStats := svr.statsCollector.GetServer()
	res = ServerInfoResp{
		Version:           version.Full(),
		BindPort:          cfg.BindPort,
		BindUdpPort:       cfg.BindUdpPort,
		VhostHttpPort:     cfg.VhostHttpPort,
		VhostHttpsPort:    cfg.VhostHttpsPort,
		KcpBindPort:       cfg.KcpBindPort,
		SubdomainHost:     cfg.SubDomainHost,
		MaxPoolCount:      cfg.MaxPoolCount,
		MaxPortsPerClient: cfg.MaxPortsPerClient,
		HeartBeatTimeout:  cfg.HeartBeatTimeout,

		TotalTrafficIn:  serverStats.TotalTrafficIn,
		TotalTrafficOut: serverStats.TotalTrafficOut,
		CurConns:        serverStats.CurConns,
		ClientCounts:    serverStats.ClientCounts,
		ProxyTypeCounts: serverStats.ProxyTypeCounts,
	}

	buf, _ = json.Marshal(&res)
	w.Write(buf)
}

type BaseOutConf struct {
	config.BaseProxyConf
}

type TcpOutConf struct {
	BaseOutConf
	RemotePort int `json:"remote_port"`
}

type UdpOutConf struct {
	BaseOutConf
	RemotePort int `json:"remote_port"`
}

type HttpOutConf struct {
	BaseOutConf
	config.DomainConf
	Locations         []string `json:"locations"`
	HostHeaderRewrite string   `json:"host_header_rewrite"`
}

type HttpsOutConf struct {
	BaseOutConf
	config.DomainConf
}

type StcpOutConf struct {
	BaseOutConf
}

type XtcpOutConf struct {
	BaseOutConf
}

func getConfByType(proxyType string) interface{} {
	switch proxyType {
	case consts.TcpProxy:
		return &TcpOutConf{}
	case consts.UdpProxy:
		return &UdpOutConf{}
	case consts.HttpProxy:
		return &HttpOutConf{}
	case consts.HttpsProxy:
		return &HttpsOutConf{}
	case consts.StcpProxy:
		return &StcpOutConf{}
	case consts.XtcpProxy:
		return &XtcpOutConf{}
	default:
		return nil
	}
}

// Get proxy info.
type ProxyStatsInfo struct {
	Name            string      `json:"name"`
	Conf            interface{} `json:"conf"`
	TodayTrafficIn  int64       `json:"today_traffic_in"`
	TodayTrafficOut int64       `json:"today_traffic_out"`
	CurConns        int64       `json:"cur_conns"`
	LastStartTime   string      `json:"last_start_time"`
	LastCloseTime   string      `json:"last_close_time"`
	Status          string      `json:"status"`
}

type GetProxyInfoResp struct {
	GeneralResponse
	Proxies []*ProxyStatsInfo `json:"proxies"`
}

// api/proxy/:type
func (svr *Service) ApiProxyByType(w http.ResponseWriter, r *http.Request) {
	var (
		buf []byte
		res GetProxyInfoResp
	)
	params := mux.Vars(r)
	proxyType := params["type"]

	defer func() {
		log.Info("Http response [%s]: code [%d]", r.URL.Path, res.Code)
		log.Info(r.URL.Path)
		log.Info(r.URL.RawPath)
	}()
	log.Info("Http request: [%s]", r.URL.Path)

	res.Proxies = svr.getProxyStatsByType(proxyType)

	buf, _ = json.Marshal(&res)
	w.Write(buf)

}

func (svr *Service) getProxyStatsByType(proxyType string) (proxyInfos []*ProxyStatsInfo) {
	proxyStats := svr.statsCollector.GetProxiesByType(proxyType)
	proxyInfos = make([]*ProxyStatsInfo, 0, len(proxyStats))
	for _, ps := range proxyStats {
		proxyInfo := &ProxyStatsInfo{}
		if pxy, ok := svr.pxyManager.GetByName(ps.Name); ok {
			content, err := json.Marshal(pxy.GetConf())
			if err != nil {
				log.Warn("marshal proxy [%s] conf info error: %v", ps.Name, err)
				continue
			}
			proxyInfo.Conf = getConfByType(ps.Type)
			if err = json.Unmarshal(content, &proxyInfo.Conf); err != nil {
				log.Warn("unmarshal proxy [%s] conf info error: %v", ps.Name, err)
				continue
			}
			proxyInfo.Status = consts.Online
		} else {
			proxyInfo.Status = consts.Offline
		}
		proxyInfo.Name = ps.Name
		proxyInfo.TodayTrafficIn = ps.TodayTrafficIn
		proxyInfo.TodayTrafficOut = ps.TodayTrafficOut
		proxyInfo.CurConns = ps.CurConns
		proxyInfo.LastStartTime = ps.LastStartTime
		proxyInfo.LastCloseTime = ps.LastCloseTime
		proxyInfos = append(proxyInfos, proxyInfo)
	}
	return
}

// Get proxy info by name.
type GetProxyStatsResp struct {
	GeneralResponse

	Name            string      `json:"name"`
	Conf            interface{} `json:"conf"`
	TodayTrafficIn  int64       `json:"today_traffic_in"`
	TodayTrafficOut int64       `json:"today_traffic_out"`
	CurConns        int64       `json:"cur_conns"`
	LastStartTime   string      `json:"last_start_time"`
	LastCloseTime   string      `json:"last_close_time"`
	Status          string      `json:"status"`
}

// api/proxy/:type/:name
func (svr *Service) ApiProxyByTypeAndName(w http.ResponseWriter, r *http.Request) {
	var (
		buf []byte
		res GetProxyStatsResp
	)
	params := mux.Vars(r)
	proxyType := params["type"]
	name := params["name"]

	defer func() {
		log.Info("Http response [%s]: code [%d]", r.URL.Path, res.Code)
	}()
	log.Info("Http request: [%s]", r.URL.Path)

	res = svr.getProxyStatsByTypeAndName(proxyType, name)

	buf, _ = json.Marshal(&res)
	w.Write(buf)
}

func (svr *Service) getProxyStatsByTypeAndName(proxyType string, proxyName string) (proxyInfo GetProxyStatsResp) {
	proxyInfo.Name = proxyName
	ps := svr.statsCollector.GetProxiesByTypeAndName(proxyType, proxyName)
	if ps == nil {
		proxyInfo.Code = 1
		proxyInfo.Msg = "no proxy info found"
	} else {
		if pxy, ok := svr.pxyManager.GetByName(proxyName); ok {
			content, err := json.Marshal(pxy.GetConf())
			if err != nil {
				log.Warn("marshal proxy [%s] conf info error: %v", ps.Name, err)
				proxyInfo.Code = 2
				proxyInfo.Msg = "parse conf error"
				return
			}
			proxyInfo.Conf = getConfByType(ps.Type)
			if err = json.Unmarshal(content, &proxyInfo.Conf); err != nil {
				log.Warn("unmarshal proxy [%s] conf info error: %v", ps.Name, err)
				proxyInfo.Code = 2
				proxyInfo.Msg = "parse conf error"
				return
			}
			proxyInfo.Status = consts.Online
		} else {
			proxyInfo.Status = consts.Offline
		}
		proxyInfo.TodayTrafficIn = ps.TodayTrafficIn
		proxyInfo.TodayTrafficOut = ps.TodayTrafficOut
		proxyInfo.CurConns = ps.CurConns
		proxyInfo.LastStartTime = ps.LastStartTime
		proxyInfo.LastCloseTime = ps.LastCloseTime
	}

	return
}

// api/traffic/:name
type GetProxyTrafficResp struct {
	GeneralResponse

	Name       string  `json:"name"`
	TrafficIn  []int64 `json:"traffic_in"`
	TrafficOut []int64 `json:"traffic_out"`
}

func (svr *Service) ApiProxyTraffic(w http.ResponseWriter, r *http.Request) {
	var (
		buf []byte
		res GetProxyTrafficResp
	)
	params := mux.Vars(r)
	name := params["name"]

	defer func() {
		log.Info("Http response [%s]: code [%d]", r.URL.Path, res.Code)
	}()
	log.Info("Http request: [%s]", r.URL.Path)

	res.Name = name
	proxyTrafficInfo := svr.statsCollector.GetProxyTraffic(name)
	if proxyTrafficInfo == nil {
		res.Code = 1
		res.Msg = "no proxy info found"
	} else {
		res.TrafficIn = proxyTrafficInfo.TrafficIn
		res.TrafficOut = proxyTrafficInfo.TrafficOut
	}

	buf, _ = json.Marshal(&res)
	w.Write(buf)
}

func (svr *Service) CorsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(r.Header)
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Headers", GetHeaders(r))
		w.Header().Set("Access-Control-Max-Age", "7200")
		fmt.Println(r.Method)
		if strings.EqualFold(r.Method, "OPTIONS") {
			w.Header().Set("Access-Control-Allow-Methods", r.Header.Get("Access-Control-Request-Method"))
			w.WriteHeader(204)
			fmt.Println(w.Header())

		} else {
			w.Header().Set("Access-Control-Allow-Methods", r.Method)
			fmt.Println(w.Header())
			next.ServeHTTP(w, r)
		}

	})
}

func GetHeaders(r *http.Request) string {
	headers := r.Header.Get("Access-Control-Request-Headers")
	separate := ", "
	if headers != "" {
		headers += separate
	}
	for k, _ := range r.Header {
		headers += k + separate
	}
	return headers[0 : len(headers)-len(separate)]
}

func (svr *Service) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenStr := r.Header.Get("token")
		tokenBytes, err := base64.StdEncoding.DecodeString(tokenStr)
		if err != nil {
			http.Error(w, util.GetJson(GetResult("40000", "Invalid token")), http.StatusOK)
			return
		}

		tokenString := string(tokenBytes)

		tokenInfo := strings.Split(tokenString, ":")
		if len(tokenInfo) != 3 {
			http.Error(w, util.GetJson(GetResult("40001", "Invalid token")), http.StatusOK)
			return
		}

		timeUnix := time.Now().Unix()
		rTime, _ := strconv.Atoi(tokenInfo[2])
		if (timeUnix-int64(rTime/1000)) > 60 || (timeUnix-int64(rTime/1000)) < (-60) {
			http.Error(w, util.GetJson(GetResult("40002", "token expired")), http.StatusOK)
			return
		}

		userToken, err := GetToken(tokenInfo[0])

		if err != nil || userToken != tokenInfo[1] {
			http.Error(w, util.GetJson(GetResult("40003", "Verification failed")), http.StatusOK)
			return
		}

		r.Header.Set("user", tokenInfo[0])
		next.ServeHTTP(w, r)

	})
}

func (svr *Service) user(w http.ResponseWriter, r *http.Request) {

	fmt.Fprint(w, util.GetJson(GetResult("0", r.Header.Get("user"))))

}

func (svr *Service) listRules(w http.ResponseWriter, r *http.Request) {

	params := mux.Vars(r)

	var rulesMap = make(map[string]Rule)
	rulesObject := ReadRules(r.Header.Get("user"))

	if params["id"] != "" {
		v := rulesObject[params["id"]]
		if v != nil {
			var rule Rule
			rule.Id, _ = strconv.Atoi(params["id"])
			rule.Name = string([]rune(v["proxy_name"].(string))[len(r.Header.Get("user"))+1:])
			rule.Protocol = v["proxy_type"].(string)
			rule.Host = "proxy.s-stars.top"
			rule.Port = strconv.Itoa(int(v["remote_port"].(float64)))
			if v["locations"] != nil {
				rule.Path = strings.Replace(strings.Trim(fmt.Sprint(v["locations"]), "[]"), " ", ",", -1)
			}
			rule.RealHost = v["local_ip"].(string)
			rule.RealPort = strconv.Itoa(int(v["local_port"].(float64)))
			rulesMap[params["id"]] = rule
		}
	} else {
		for k, v := range rulesObject {

			var rule Rule
			rule.Id, _ = strconv.Atoi(k)
			rule.Name = string([]rune(v["proxy_name"].(string))[len(r.Header.Get("user"))+1:])
			rule.Protocol = v["proxy_type"].(string)
			rule.Host = "proxy.s-stars.top"
			rule.Port = strconv.Itoa(int(v["remote_port"].(float64)))

			if v["locations"] != nil {
				rule.Path = strings.Replace(strings.Trim(fmt.Sprint(v["locations"]), "[]"), " ", ",", -1)
			}
			rule.RealHost = v["local_ip"].(string)
			rule.RealPort = strconv.Itoa(int(v["local_port"].(float64)))
			rulesMap[k] = rule
		}
	}

	if _, err := fmt.Fprint(w, util.GetJson(GetResult("0", rulesMap))); err != nil {
		fmt.Printf("%s", err.Error())
	}
}

func (svr *Service) saveRule(w http.ResponseWriter, r *http.Request) {
	user := r.Header.Get("user")
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		if _, err := fmt.Fprint(w, util.GetJson(GetResult("50002", err.Error()))); err != nil {
			fmt.Printf("%s", err.Error())
		}
		return
	}
	var rule Rule
	fmt.Println(string(body))
	if err = json.Unmarshal(body, &rule); err != nil {
		if _, err := fmt.Fprint(w, util.GetJson(GetResult("50003", err.Error()))); err != nil {
			fmt.Printf("%s", err.Error())
		}
	}

	rulesObject := ReadRules(r.Header.Get("user"))

	if rule.Name == "" {
		rule.Name = strconv.Itoa(rule.Id)
	}
	rulesObject[strconv.Itoa(rule.Id)] = map[string]interface{}{
		"proxy_name":     user + "." + rule.Name,
		"proxy_type":     rule.Protocol,
		"remote_port":    Default(strconv.Atoi(rule.Port)),
		"locations":      strings.Split(rule.Path, ","),
		"local_ip":       rule.RealHost,
		"local_port":     Default(strconv.Atoi(rule.RealPort)),
		"use_encryption": true,
	}

	if _, err := fmt.Fprint(w, util.GetJson(GetResult("0", WriteRules(user, rulesObject)))); err != nil {
		fmt.Printf("%s", err.Error())
	}

	for _, v := range svr.ctlManager.ctlsByRunId {
		v.conn.Close()
	}
}

func Default(v interface{}, err error) interface{} {
	if err != nil {
		fmt.Println(err.Error())
		return v
	} else {
		return v
	}

}

func (svr *Service) deleteRule(w http.ResponseWriter, r *http.Request) {
	user := r.Header.Get("user")

	params := mux.Vars(r)
	if params["id"] == "" {
		if _, err := fmt.Fprint(w, util.GetJson(GetResult("0", ""))); err != nil {
			fmt.Printf("%s", err.Error())
		}
		return
	}
	rulesObject := ReadRules(r.Header.Get("user"))

	delete(rulesObject, params["id"])

	if _, err := fmt.Fprint(w, util.GetJson(GetResult("0", WriteRules(user, rulesObject)))); err != nil {
		fmt.Printf("%s", err.Error())
	}

	for _, v := range svr.ctlManager.ctlsByRunId {
		v.conn.Close()
	}

}

type Result struct {
	State string      `json:"state"`
	Data  interface{} `json:"data"`
}

type Rule struct {
	Id        int      `json:"id"`
	Name      string   `json:"name"`
	Protocol  string   `json:"protocol"`
	Host      string   `json:"host"`
	Port      string   `json:"port"`
	Path      string   `json:"path"`
	RealHost  string   `json:"realHost"`
	RealPort  string   `json:"realPort"`
	RealPath  string   `json:"realPath"`
	WhiteList []string `json:"whiteList"`
}

func GetResult(errorCode string, data interface{}) interface{} {
	result := Result{}
	result.Data = data
	result.State = errorCode
	return result
}

func GetToken(user string) (token string, err error) {
	f, err := os.Open("/var/frps/" + user + ".token")
	if err != nil {
		return
	}
	data, err := ioutil.ReadAll(f)
	if err != nil {
		return
	}
	token = strings.Trim(string(data[:]), "\r\n")
	token = strings.Trim(token, "\r")
	token = strings.Trim(token, "\n")
	token = strings.Trim(token, " ")
	token = strings.Trim(token, "	")
	return
}

func ReadRules(user string) (rules map[string]map[string]interface{}) {
	data, err := ioutil.ReadFile("/var/frps/" + user + ".db") // os.Open("db/" + user + ".db")
	if err != nil {
		log.Info("[%s] [%s]", "/var/frps/"+user+".db", err.Error())
		return
	}
	if err := json.Unmarshal([]byte(data), &rules); err != nil {
		fmt.Printf("%s", err.Error())
	}
	if err != nil {
		return
	}
	return
}

func WriteRules(user string, rules interface{}) bool {
	err := ioutil.WriteFile("/var/frps/"+user+".db", []byte(util.GetJson(rules)), 0644)
	if err != nil {
		log.Info("[%s] [%s]", "/var/frps/"+user+".db", err.Error())
		return false
	}
	return true
}
