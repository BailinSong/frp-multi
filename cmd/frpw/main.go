package main

//import "time"

//import (
//	"encoding/base64"
//	"encoding/json"
//	"fmt"
//	"frp/utils/log"
//	"frp/utils/util"
//	"github.com/gorilla/mux"
//	"io/ioutil"
//	"net"
//	"net/http"
//	"os"
//	"strconv"
//	"strings"
//	"time"
//)

//var (
//	httpServerReadTimeout  = 10 * time.Second
//	httpServerWriteTimeout = 10 * time.Second
//)

//func main() {
//	//crypto.DefaultSalt = "frp"
//	fmt.Printf("Http server on %s:%d\n", "0.0.0.0", 8080)
//	RunHttpServer("0.0.0.0", 8080)
//}

//func RunHttpServer(addr string, port int) (err error) {
//	// url router
//	router := mux.NewRouter()
//
//	//user, passwd := g.GlbServerCfg.DashboardUser, g.GlbServerCfg.DashboardPwd
//	router.Use(Middleware)
//
//	// api, see dashboard_api.go
//	router.HandleFunc("/user", user).Methods("GET")
//	router.HandleFunc("/rules", listRules).Methods("GET")
//	router.HandleFunc("/rules", saveRule).Methods("POST")
//	router.HandleFunc("/rules", saveRule).Methods("PUT")
//	router.HandleFunc("/rules/{id}", listRules).Methods("GET")
//	router.HandleFunc("/rules/{id}", deleteRule).Methods("DELETE")
//
//	address := fmt.Sprintf("%s:%d", addr, port)
//	server := &http.Server{
//		Addr:         address,
//		Handler:      router,
//		ReadTimeout:  httpServerReadTimeout,
//		WriteTimeout: httpServerWriteTimeout,
//	}
//	if address == "" {
//		address = ":http"
//	}
//	ln, err := net.Listen("tcp", address)
//	if err != nil {
//		return err
//	}
//
//	if err:=server.Serve(ln);err!= nil{
//		fmt.Printf("%s",err.Error())
//	}
//	return
//}

//func Middleware(next http.Handler) http.Handler {
//	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		tokenStr := r.Header.Get("token")
//		tokenBytes, err := base64.StdEncoding.DecodeString(tokenStr)
//		if err != nil {
//			http.Error(w, util.GetJson(GetResult("40000", "Invalid token")), http.StatusOK)
//			return
//		}
//
//		tokenString := string(tokenBytes)
//
//		tokenInfo := strings.Split(tokenString, ":")
//
//		timeUnix := time.Now().Unix()
//		rTime, _ := strconv.Atoi(tokenInfo[2])
//		if (timeUnix-int64(rTime/1000)) > 60 || (timeUnix-int64(rTime/1000)) < (-60) {
//			http.Error(w, util.GetJson(GetResult("40002", "token expired")), http.StatusOK)
//			return
//		}
//
//		userToken, err := GetToken(tokenInfo[0])
//
//		if err != nil || userToken != tokenInfo[1] {
//			http.Error(w, util.GetJson(GetResult("40001", "Verification failed")), http.StatusOK)
//			return
//		}
//
//		r.Header.Set("user", tokenInfo[0])
//		next.ServeHTTP(w, r)
//
//	})
//}
//
//func user(w http.ResponseWriter, r *http.Request) {
//
//	fmt.Fprint(w, util.GetJson(GetResult("0", r.Header.Get("user"))))
//
//}
//
//func listRules(w http.ResponseWriter, r *http.Request) {
//
//	params := mux.Vars(r)
//
//	var rulesMap = make(map[string]Rule)
//	rulesObject := ReadRules(r.Header.Get("user"))
//
//	if params["id"] != "" {
//		v := rulesObject[params["id"]]
//		if v != nil {
//			var rule Rule
//			rule.Id, _ = strconv.Atoi(params["id"])
//			rule.Name = string([]rune(v["proxy_name"].(string))[len(r.Header.Get("user"))+1:])
//			rule.Protocol = v["proxy_type"].(string)
//			rule.Host = "proxy.s-stars.top"
//			rule.Port = int(v["remote_port"].(float64))
//			if v["locations"] != nil {
//				rule.Path = v["locations"].(string)
//			}
//			rule.RealHost = v["local_ip"].(string)
//			rule.RealPort = int(v["local_port"].(float64))
//			rulesMap[params["id"]] = rule
//		}
//	} else {
//		for k, v := range rulesObject {
//
//			var rule Rule
//			rule.Id, _ = strconv.Atoi(k)
//			rule.Name = string([]rune(v["proxy_name"].(string))[len(r.Header.Get("user"))+1:])
//			rule.Protocol = v["proxy_type"].(string)
//			rule.Host = "proxy.s-stars.top"
//			rule.Port = int(v["remote_port"].(float64))
//			if v["locations"] != nil {
//				rule.Path = v["locations"].(string)
//			}
//			rule.RealHost = v["local_ip"].(string)
//			rule.RealPort = int(v["local_port"].(float64))
//			rulesMap[k] = rule
//		}
//	}
//
//	if _,err:=fmt.Fprint(w, util.GetJson(GetResult("0", rulesMap)));err!= nil{
//		fmt.Printf("%s",err.Error())
//	}
//}
//
//func saveRule(w http.ResponseWriter, r *http.Request) {
//	user := r.Header.Get("user")
//	body, err := ioutil.ReadAll(r.Body)
//	if err != nil {
//		if _,err:=fmt.Fprint(w, util.GetJson(GetResult("50002", err.Error())));err!= nil{
//			fmt.Printf("%s",err.Error())
//		}
//		return
//	}
//	var rule Rule
//	if err = json.Unmarshal(body,&rule);err != nil{
//		if _,err:=fmt.Fprint(w, util.GetJson(GetResult("50003", err.Error())));err!= nil{
//			fmt.Printf("%s",err.Error())
//		}
//	}
//
//	rulesObject := ReadRules(r.Header.Get("user"))
//
//
//	if rule.Name == "" {
//		rule.Name=strconv.Itoa(rule.Id)
//	}
//	rulesObject[strconv.Itoa(rule.Id)]= map[string]interface{}{
//		"proxy_name":user+"."+rule.Name,
//		"proxy_type":rule.Protocol,
//		"remote_port":rule.Port,
//		"locations":rule.Path,
//		"local_ip":rule.RealHost,
//		"local_port":rule.RealPort,
//	}
//
//	if _,err:=fmt.Fprint(w, util.GetJson(GetResult("0", WriteRules(user,rulesObject))));err!= nil{
//		fmt.Printf("%s",err.Error())
//	}
//}
//
//func deleteRule(w http.ResponseWriter, r *http.Request) {
//	user := r.Header.Get("user")
//
//	params := mux.Vars(r)
//	if params["id"] == "" {
//		if _,err:=fmt.Fprint(w, util.GetJson(GetResult("0", "")));err!= nil{
//			fmt.Printf("%s",err.Error())
//		}
//		return
//	}
//	rulesObject := ReadRules(r.Header.Get("user"))
//
//	delete(rulesObject, params["id"])
//
//	if _,err:=fmt.Fprint(w, util.GetJson(GetResult("0", WriteRules(user,rulesObject))));err!= nil{
//		fmt.Printf("%s",err.Error())
//	}
//}
//
//type Result struct {
//	State string      `json:"state"`
//	Data  interface{} `json:"data"`
//}
//
//type Rule struct {
//	Id        int      `json:"id"`
//	Name      string   `json:"name"`
//	Protocol  string   `json:"protocol"`
//	Host      string   `json:"host"`
//	Port      int      `json:"port"`
//	Path      string   `json:"path"`
//	RealHost  string   `json:"realHost"`
//	RealPort  int      `json:"realPort"`
//	RealPath  string   `json:"realPath"`
//	WhiteList []string `json:"whiteList"`
//}
//
//func GetResult(errorCode string, data interface{}) interface{} {
//	result := Result{}
//	result.Data = data
//	result.State = errorCode
//	return result
//}
//
//func GetToken(user string) (token string, err error) {
//	f, err := os.Open("db/" + user + ".token")
//	if err != nil {
//		return
//	}
//	data, err := ioutil.ReadAll(f)
//	if err != nil {
//		return
//	}
//	token = strings.Trim(string(data[:]), "\r\n")
//	token = strings.Trim(token, "\r")
//	token = strings.Trim(token, "\n")
//	token = strings.Trim(token, " ")
//	token = strings.Trim(token, "	")
//	return
//}
//
//func ReadRules(user string) (rules map[string]map[string]interface{}) {
//	data, err :=  ioutil.ReadFile("db/" + user + ".db")// os.Open("db/" + user + ".db")
//	if err != nil {
//		log.Info("[%s] [%s]","db/" + user + ".db",err.Error())
//		return
//	}
//	if err:=json.Unmarshal([]byte(data), &rules);err!= nil{
//		fmt.Printf("%s",err.Error())
//	}
//	if err != nil {
//		return
//	}
//	return
//}
//
//func WriteRules(user string, rules interface{}) bool{
//	err := ioutil.WriteFile("db/" + user + ".db",[]byte(util.GetJson(rules)),0644)
//	if err != nil {
//		log.Info("[%s] [%s]","db/" + user + ".db",err.Error())
//		return false
//	}
//	return true
//}
