package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"strings"
	"sync"
	"time"

	//"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
	// "github.com/pkg/profile"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	b64 "encoding/base64"

	"github.com/gorilla/websocket"
	"github.com/hollychen503/htpasswd"
)

var port string
var filePath string

func init() {
	flag.StringVar(&port, "port", "80", "give me a port number")
	flag.StringVar(&filePath, "htpasswd", "./htpasswd", "htpasswd file path")
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func main() {
	fmt.Println("0.2.1")
	// defer profile.Start().Stop()
	flag.Parse()

	log.Println("htpasswd:", filePath)
	http.HandleFunc("/echo", echoHandler)
	http.HandleFunc("/bench", benchHandler)
	http.HandleFunc("/", whoamI)

	http.HandleFunc("/check", whoAreU)
	http.HandleFunc("/reject", reject)

	http.HandleFunc("/api", api)
	http.HandleFunc("/health", healthHandler)
	fmt.Println("Starting up on port " + port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func printBinary(s []byte) {
	fmt.Printf("Received b:")
	for n := 0; n < len(s); n++ {
		fmt.Printf("%d,", s[n])
	}
	fmt.Printf("\n")
}
func benchHandler(w http.ResponseWriter, r *http.Request) {
	// body := "Hello World\n"
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Content-Type", "text/plain")
	// fmt.Fprint(w, body)
}
func echoHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
	for {
		messageType, p, err := conn.ReadMessage()
		if err != nil {
			return
		}
		printBinary(p)
		err = conn.WriteMessage(messageType, p)
		if err != nil {
			return
		}
	}
}

func reject(w http.ResponseWriter, req *http.Request) {
	log.Println("++++++++++++++++++++++++++++++++++++++++++++++++")
	log.Println("U are rejected!!!")
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)

	//-------- ugly code :-D

	u, _ := url.Parse(req.URL.String())
	queryParams := u.Query()
	wait := queryParams.Get("wait")
	if len(wait) > 0 {
		duration, err := time.ParseDuration(wait)
		if err == nil {
			time.Sleep(duration)
		}
	}
	hostname, _ := os.Hostname()
	fmt.Fprintln(w, "Hostname:", hostname)
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		// handle err
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			fmt.Fprintln(w, "IP:", ip)
		}
	}
	req.Write(w)

}

func whoAreU(w http.ResponseWriter, req *http.Request) {
	log.Println("++++++++++++++++++++++++++++++++++++++++++++++++")
	dump, _ := httputil.DumpRequest(req, true)
	fmt.Println(string(dump))

	//--------

	u, _ := url.Parse(req.URL.String())
	queryParams := u.Query()
	wait := queryParams.Get("wait")
	if len(wait) > 0 {
		duration, err := time.ParseDuration(wait)
		if err == nil {
			time.Sleep(duration)
		}
	}
	hostname, _ := os.Hostname()
	fmt.Fprintln(w, "Hostname:", hostname)
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		// handle err
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			fmt.Fprintln(w, "IP:", ip)
		}
	}
	req.Write(w)

}

func whoamI(w http.ResponseWriter, req *http.Request) {
	//u, _ := url.Parse(req.URL.String())
	log.Println("++++++++++++++++++++++++++++++++++++++++++++++++")
	dump, _ := httputil.DumpRequest(req, true)
	fmt.Println(string(dump))
	log.Println("------------------------------------------------")

	// 获取用户名，密码
	// Authorization: Basic dGVzdHVzZXI6dGVzdHBhc3N3b3Jk
	usrpw := req.Header.Get("Authorization")
	if len(usrpw) == 0 {
		fmt.Println(" without Authorization header. ignore.")
		return
	}
	fmt.Println(usrpw)
	upslice := strings.Fields(usrpw)
	if len(upslice) < 2 {
		fmt.Println(" invalid basic Authorization info ")
		return
	}

	sDec, err := b64.StdEncoding.DecodeString(upslice[1])
	if err != nil {
		fmt.Println("  can not decode basic auth info")
		return
	}
	fmt.Println(string(sDec))
	decSli := strings.Split(string(sDec), ":")
	if len(decSli) < 2 {
		fmt.Println("  mal format of basic auth info")
		return
	}
	tmpName := decSli[0]
	tmpPw := decSli[1]

	//tmpPwHash := htpasswd.HashedPasswords(map[string]string{})

	//err = tmpPwHash.SetPassword(tmpName, tmpPw, htpasswd.HashBCrypt)
	//if err != nil {
	//	fmt.Println("failed to gen password")
	//	return
	//}

	///
	passwords, err := htpasswd.ParseHtpasswdFile(filePath)
	if err != nil {
		//w.WriteHeader(http.StatusInternalServerError)
		log.Println("failed to parse htpasswd file on", filePath)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	for k, v := range passwords {
		fmt.Println(k, ":", v)
	}
	/*
		if tmpPwHash[tmpName] != passwords[tmpName] {
			log.Println(" invalid password")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
	*/
	//  CompareHashAndPassword(hashedPassword, password []byte)
	fmt.Println("hashedPw:", passwords[tmpName])
	fmt.Println("pw:", tmpPw)
	err = bcrypt.CompareHashAndPassword([]byte(passwords[tmpName]), []byte(tmpPw))
	if err != nil {
		fmt.Println(err)
		log.Println(" invalid password")
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	fmt.Println("matched!")

	return
	/*
		queryParams := u.Query()
		wait := queryParams.Get("wait")
		if len(wait) > 0 {
			duration, err := time.ParseDuration(wait)
			if err == nil {
				time.Sleep(duration)
			}
		}
		hostname, _ := os.Hostname()
		fmt.Fprintln(w, "Hostname:", hostname)
		ifaces, _ := net.Interfaces()
		for _, i := range ifaces {
			addrs, _ := i.Addrs()
			// handle err
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				fmt.Fprintln(w, "IP:", ip)
			}
		}
		req.Write(w)
	*/
}

func api(w http.ResponseWriter, req *http.Request) {
	hostname, _ := os.Hostname()
	data := struct {
		Hostname string      `json:"hostname,omitempty"`
		IP       []string    `json:"ip,omitempty"`
		Headers  http.Header `json:"headers,omitempty"`
	}{
		hostname,
		[]string{},
		req.Header,
	}

	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		// handle err
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			data.IP = append(data.IP, ip.String())
		}
	}
	json.NewEncoder(w).Encode(data)
}

type healthState struct {
	StatusCode int
}

var currentHealthState = healthState{200}
var mutexHealthState = &sync.RWMutex{}

func healthHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPost {
		var statusCode int
		err := json.NewDecoder(req.Body).Decode(&statusCode)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
		} else {
			fmt.Printf("Update health check status code [%d]\n", statusCode)
			mutexHealthState.Lock()
			defer mutexHealthState.Unlock()
			currentHealthState.StatusCode = statusCode
		}
	} else {
		mutexHealthState.RLock()
		defer mutexHealthState.RUnlock()
		w.WriteHeader(currentHealthState.StatusCode)
	}
}
