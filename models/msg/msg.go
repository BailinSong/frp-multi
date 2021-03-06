// Copyright 2016 frp, frp@gmail.com
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

package msg

import "net"

const (
	TypeLogin              = 'a'
	TypeLoginResp          = 'b'
	TypeNewProxy           = 'c'
	TypeNewProxyResp       = 'd'
	TypeCloseProxy         = 'e'
	TypeNewWorkConn        = 'f'
	TypeReqWorkConn        = 'g'
	TypeStartWorkConn      = 'h'
	TypeNewVisitorConn     = 'i'
	TypeNewVisitorConnResp = 'j'
	TypePing               = 'k'
	TypePong               = 'l'
	TypeUdpPacket          = 'm'
	TypeNatHoleVisitor     = 'n'
	TypeNatHoleClient      = 'o'
	TypeNatHoleResp        = 'p'
	TypeNatHoleSid         = 'q'
)

var (
	msgTypeMap = map[byte]interface{}{
		TypeLogin:              Login{},
		TypeLoginResp:          LoginResp{},
		TypeNewProxy:           NewProxy{},
		TypeNewProxyResp:       NewProxyResp{},
		TypeCloseProxy:         CloseProxy{},
		TypeNewWorkConn:        NewWorkConn{},
		TypeReqWorkConn:        ReqWorkConn{},
		TypeStartWorkConn:      StartWorkConn{},
		TypeNewVisitorConn:     NewVisitorConn{},
		TypeNewVisitorConnResp: NewVisitorConnResp{},
		TypePing:               Ping{},
		TypePong:               Pong{},
		TypeUdpPacket:          UdpPacket{},
		TypeNatHoleVisitor:     NatHoleVisitor{},
		TypeNatHoleClient:      NatHoleClient{},
		TypeNatHoleResp:        NatHoleResp{},
		TypeNatHoleSid:         NatHoleSid{},
	}
)

// When frpc start, client send this message to login to server.
type Login struct {
	Version      string `json:"version"`
	Hostname     string `json:"hostname"`
	Os           string `json:"os"`
	Arch         string `json:"arch"`
	User         string `json:"user"`
	PrivilegeKey string `json:"privilege_key"`
	Timestamp    int64  `json:"timestamp"`
	RunId        string `json:"run_id"`

	// Some global configures.
	PoolCount int `json:"pool_count"`
}

type LoginResp struct {
	Version       string `json:"version"`
	RunId         string `json:"run_id"`
	ServerUdpPort int    `json:"server_udp_port"`
	Error         string `json:"error"`
	ProxyConfig   string `json:"proxy_config"`
}

// When frpc login success, send this message to frps for running a new proxy.
type NewProxy struct {

	ProxyName      string `json:"proxy_name"`
	ProxyType      string `json:"proxy_type"`
	UseEncryption  bool   `json:"use_encryption"`
	UseCompression bool   `json:"use_compression"`
	Group          string `json:"group"`
	GroupKey       string `json:"group_key"`

	// tcp and udp only
	RemotePort int `json:"remote_port"`

	// http and https only
	CustomDomains     []string          `json:"custom_domains"`
	SubDomain         string            `json:"subdomain"`
	Locations         []string          `json:"locations"`
	HttpUser          string            `json:"http_user"`
	HttpPwd           string            `json:"http_pwd"`
	HostHeaderRewrite string            `json:"host_header_rewrite"`
	Headers           map[string]string `json:"headers"`

	// stcp
	Sk string `json:"sk"`
	
	// local info
	LocalIP           string `json:"local_ip"`
	LocalPort        int `json:"local_port"`
}

type NewProxyResp struct {
	ProxyName  string `json:"proxy_name"`
	RemoteAddr string `json:"remote_addr"`
	Error      string `json:"error"`
}

type CloseProxy struct {
	ProxyName string `json:"proxy_name"`
}

type NewWorkConn struct {
	RunId string `json:"run_id"`
}

type ReqWorkConn struct {
}

type StartWorkConn struct {
	ProxyName string `json:"proxy_name"`
}

type NewVisitorConn struct {
	ProxyName      string `json:"proxy_name"`
	SignKey        string `json:"sign_key"`
	Timestamp      int64  `json:"timestamp"`
	UseEncryption  bool   `json:"use_encryption"`
	UseCompression bool   `json:"use_compression"`
}

type NewVisitorConnResp struct {
	ProxyName string `json:"proxy_name"`
	Error     string `json:"error"`
}

type Ping struct {
}

type Pong struct {
}

type UdpPacket struct {
	Content    string       `json:"c"`
	LocalAddr  *net.UDPAddr `json:"l"`
	RemoteAddr *net.UDPAddr `json:"r"`
}

type NatHoleVisitor struct {
	ProxyName string `json:"proxy_name"`
	SignKey   string `json:"sign_key"`
	Timestamp int64  `json:"timestamp"`
}

type NatHoleClient struct {
	ProxyName string `json:"proxy_name"`
	Sid       string `json:"sid"`
}

type NatHoleResp struct {
	Sid         string `json:"sid"`
	VisitorAddr string `json:"visitor_addr"`
	ClientAddr  string `json:"client_addr"`
	Error       string `json:"error"`
}

type NatHoleSid struct {
	Sid string `json:"sid"`
}
