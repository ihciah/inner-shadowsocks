package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"time"

	"github.com/ihciah/go-shadowsocks2/core"
)

const (
	channel_buffer_size    = 128
	default_Maxfail        = 10
	default_Recovertime    = 600
	default_Listen         = "0.0.0.0"
	default_start_timeout  = 8
	default_remote_timeout = 60
	default_inside_timeout = 60
)

type Server struct {
	server string
	ciph   core.Cipher
	addr   string
}

type Config struct {
	listenAddr net.TCPAddr
	servers    []Server
	auth       bool
	username   []byte
	password   []byte
	scheduler  Scheduler
	verbose    bool
	rtimeout   time.Duration
	itimeout   time.Duration
	stimeout   time.Duration
}

type userConfig struct {
	Listen        string   `json:"listen"`
	Port          int      `json:"port"`
	Auth          bool     `json:"auth"`
	Username      string   `json:"username"`
	Password      string   `json:"password"`
	Servers       []string `json:"servers"`
	Maxfail       int      `json:"maxfail"`
	Recovertime   int      `json:"recovertime"`
	Starttimeout  int      `json:"starttimeout"`
	Remotetimeout int      `json:"remotetimeout"`
	Insidetimeout int      `json:"insidetimeout"`
}

type timeoutConn struct {
	net.Conn
	timelimit time.Duration
	starttime time.Duration
	active    bool
}

func (config *Config) log(f string, v ...interface{}) {
	if config.verbose {
		log.Printf(f, v...)
	}
}

func (tc timeoutConn) heartbeat() {
	if tc.active {
		tc.Conn.SetDeadline(time.Now().Add(tc.timelimit))
	} else {
		tc.Conn.SetDeadline(time.Now().Add(tc.starttime))
		tc.active = true
	}
}
func (tc timeoutConn) Read(buf []byte) (int, error) {
	tc.heartbeat()
	return tc.Conn.Read(buf)
}

func (tc timeoutConn) Write(buf []byte) (int, error) {
	tc.heartbeat()
	return tc.Conn.Write(buf)
}

func (config *Config) StartServer() {
	listener, err := net.ListenTCP("tcp", &config.listenAddr)
	defer listener.Close()
	if err != nil {
		panic("[inner-ss] Cannot listen on given ip and port!")
	}
	config.log("[inner-ss] Auth: %t, RemoteTimeout: %d sec, InsideTimeout: %d sec.", config.auth, config.rtimeout/time.Nanosecond, config.itimeout/time.Nanosecond)
	config.log("[inner-ss] Listening %s on port %d.", config.listenAddr.IP, config.listenAddr.Port)
	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			config.log("[inner-ss] Failed to accept %s", err)
			continue
		}
		config.log("[inner-ss] Accept connection from %s", conn.RemoteAddr())
		go config.handleConnection(conn)
	}
}

func bytein(y []byte, x byte) bool {
	for _, b := range y {
		if b == x {
			return true
		}
	}
	return false
}

func (config *Config) handleConnection(conn *net.TCPConn) error {
	defer conn.Close()
	conn.SetKeepAlive(true)
	if err := config.handleSocksEncrypt(conn); err != nil {
		config.log("[inner-ss] Error when validating user. %s", err)
		return err
	}
	addr, err := getAddr(conn)
	if err != nil {
		config.log("[inner-ss] Error when getAddr. %s", err)
		return err
	}
	server_id := config.scheduler.get()
	server, ciph := config.servers[server_id].addr, config.servers[server_id].ciph
	rc, err := net.Dial("tcp", server)
	if err != nil {
		config.log("[inner-ss] Cannot connect to shadowsocks server %s\n", server)
		config.scheduler.report_fail(server_id)
		return err
	}
	config.scheduler.report_success(server_id)
	defer rc.Close()
	rc.(*net.TCPConn).SetKeepAlive(true)
	rc = ciph.StreamConn(rc)
	if _, err := rc.Write(addr); err != nil {
		return err
	}
	_, _, rerr, err := relay(rc, conn, config.rtimeout, config.itimeout, config.stimeout)
	if rerr != nil {
		config.log("[inner-ss] Remote connection error. %s", rerr)
		return rerr
	}
	return err
}

func (config *Config) handleSocksEncrypt(conn *net.TCPConn) error {
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	methods := buf[2:n]
	auth := byte(0x00)
	if config.auth {
		auth = 0x02
	}
	if buf[0] == 0x05 && !bytein(methods, auth) {
		return errors.New("Not Socks5 or auth type incorrect.")
	}
	conn.Write([]byte{0x05, auth})
	if config.auth {
		n, err = conn.Read(buf)
		if err != nil {
			return err
		}
		if n < 3 || n < int(buf[1])+3 {
			return errors.New("Data not correct.")
		}
		username_len := int(buf[1])
		username := buf[2 : 2+username_len]
		password := buf[3+username_len : n]
		if bytes.Equal(username, config.username) && bytes.Equal(password, config.password) {
			conn.Write([]byte{0x01, 0x00})
			return nil
		}
		return errors.New("Invalid username or password.")
	}
	return nil
}

func getAddr(conn *net.TCPConn) ([]byte, error) {
	buf := make([]byte, 259)
	n, err := conn.Read(buf)
	if err != nil || n < 7 {
		return nil, err
	}
	var dstAddr []byte
	switch buf[3] {
	case 0x01:
		if n < 6+net.IPv4len {
			return nil, errors.New("Invalid packet.")
		}
		dstAddr = buf[3 : 6+net.IPv4len]
	case 0x03:
		if n < 8 || n < 6+int(buf[4]) {
			return nil, errors.New("Invalid packet.")
		}
		dstAddr = buf[3 : 7+int(buf[4])]
	case 0x04:
		if n < 6+net.IPv6len {
			return nil, errors.New("Invalid packet.")
		}
		dstAddr = buf[3 : 6+net.IPv6len]
	default:
		return nil, errors.New("Invalid packet.")
	}

	switch buf[1] {
	case 0x01:
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10, 0x10})
	default:
		conn.Write([]byte{0x05, 0x07})
		return nil, errors.New("Unsupported command.")
	}
	return dstAddr, nil
}

func relay(left, right net.Conn, rtimeout, itimeout, stimeout time.Duration) (int64, int64, error, error) {
	tleft := timeoutConn{Conn: left, timelimit: rtimeout, starttime: stimeout}
	tright := timeoutConn{Conn: right, timelimit: itimeout, starttime: stimeout}
	type res struct {
		N   int64
		Err error
	}
	ch := make(chan res)

	go func() {
		n, err := io.Copy(tright, tleft)
		ch <- res{n, err}
	}()
	n, err := io.Copy(tleft, tright)
	rs := <-ch
	return n, rs.N, err, rs.Err
}

func parseURL(s string) (addr, cipher, password string, err error) {
	u, err := url.Parse(s)
	if err != nil {
		return
	}

	addr = u.Host
	if u.User != nil {
		cipher = u.User.Username()
		password, _ = u.User.Password()
	}
	return
}

func LoadUserConfig(config_file string, verbose bool) (Config, error) {
	user_config := userConfig{Maxfail: default_Maxfail, Recovertime: default_Recovertime, Listen: default_Listen,
		Remotetimeout: default_remote_timeout, Insidetimeout: default_inside_timeout, Starttimeout: default_start_timeout}
	config := Config{verbose: verbose}
	data, err := ioutil.ReadFile(config_file)
	if err != nil {
		return config, err
	}
	if err := json.Unmarshal(data, &user_config); err != nil {
		return config, err
	}
	if user_config.Listen == "" || user_config.Port == 0 {
		return config, errors.New("Cannot load config.")
	}
	config.listenAddr = net.TCPAddr{IP: net.ParseIP(user_config.Listen), Port: user_config.Port}
	config.auth, config.username, config.password = user_config.Auth, []byte(user_config.Username), []byte(user_config.Password)
	config.servers = make([]Server, 0, len(config.servers))
	for _, st := range user_config.Servers {
		s, err := makeServer(st)
		if err != nil {
			continue
		}
		config.servers = append(config.servers, s)
	}
	config.scheduler = Scheduler{}
	config.scheduler.init(len(config.servers), user_config.Maxfail, channel_buffer_size, user_config.Recovertime, verbose)
	config.rtimeout = time.Duration(user_config.Remotetimeout) * time.Second
	config.itimeout = time.Duration(user_config.Insidetimeout) * time.Second
	config.stimeout = time.Duration(user_config.Starttimeout) * time.Second
	return config, nil
}

func makeServer(s string) (Server, error) {
	addr, cipher, password, err := parseURL(s)
	if err != nil {
		return Server{}, err
	}
	ciph, err := core.PickCipher(cipher, []byte{}, password)
	if err != nil {
		return Server{}, err
	}
	return Server{s, ciph, addr}, nil
}

func main() {
	var config_file string
	var verbose bool
	flag.BoolVar(&verbose, "v", false, "verbose mode")
	flag.StringVar(&config_file, "c", "config.json", "config file path")
	flag.Parse()

	c, err := LoadUserConfig(config_file, verbose)
	if err != nil {
		log.Println("Error!", err)
		return
	}
	c.StartServer()
}
