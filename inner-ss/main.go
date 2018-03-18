package main

import (
	"net"
	"log"
	"errors"
	"bytes"
	"io"
	"time"
	"flag"
	"net/url"
	"io/ioutil"
	"encoding/json"

	"github.com/ihciah/go-shadowsocks2/core"
)

const (
	channel_buffer_size = 128
	default_Maxfail = 10
	default_Recovertime = 600
	default_Listen = "0.0.0.0"
)

type Server struct{
	server string
	ciph core.Cipher
	addr string
}

type Config struct {
	listenAddr net.TCPAddr
	servers []Server
	auth bool
	username []byte
	password []byte
	scheduler Scheduler
	verbose bool
}

type userConfig struct{
	Listen string `json:"listen"`
	Port int `json:"port"`
	Auth bool `json:"auth"`
	Username string `json:"username"`
	Password string `json:"password"`
	Servers []string `json:"servers"`
	Maxfail int `json:"maxfail"`
	Recovertime int `json:"recovertime"`
}

func (config *Config)log(f string, v ...interface{}) {
	if config.verbose {
		log.Printf(f, v...)
	}
}

func (config *Config) StartServer() {
	listener, err := net.ListenTCP("tcp", &config.listenAddr)
	defer listener.Close()
	if err != nil{
		panic("Cannot listen")
	}
	for{
		conn, err := listener.AcceptTCP()
		if err != nil{
			config.log("Failed to accept %s", err)
			continue
		}
		config.log("Accept connection from %s", conn.RemoteAddr())
		go config.handleConnection(conn)
	}
}

func bytein(y []byte, x byte) bool{
	for _, b := range y{
		if b == x{
			return true
		}
	}
	return false
}

func (config *Config) handleConnection(conn *net.TCPConn) error {
	defer conn.Close()
	conn.SetKeepAlive(true)
	if err := config.handleSocksEncrypt(conn); err != nil{
		config.log("Error when validating user. %s", err)
		return err
	}
	addr, err := getAddr(conn)
	if err != nil{
		config.log("Error when getAddr. %s", err)
		return err
	}
	server_id := config.scheduler.get()
	server, ciph := config.servers[server_id].addr, config.servers[server_id].ciph
	rc, err := net.Dial("tcp", server)
	if err != nil {
		config.log("Cannot connect to shadowsocks server %s\n", server)
		config.scheduler.report_fail(server_id)
		return err
	}
	config.scheduler.report_success(server_id)
	defer rc.Close()
	rc.(*net.TCPConn).SetKeepAlive(true)
	rc = ciph.StreamConn(rc)
	if _, err = rc.Write(addr); err != nil{
		return err
	}
	if _, _, err = relay(rc, conn); err != nil{
		if err, ok := err.(net.Error); ok && err.Timeout() {
			return nil
		}
		return err
	}
	return nil
}

func (config *Config) handleSocksEncrypt(conn *net.TCPConn) error{
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil{
		return err
	}
	methods := buf[2:n]
	auth := byte(0x00)
	if config.auth{
		auth = 0x02
	}
	if buf[0] == 0x05 && !bytein(methods, auth){
		return errors.New("Not Socks5 or auth type incorrect.")
	}
	conn.Write([]byte{0x05, auth})
	if config.auth{
		n, err = conn.Read(buf)
		if err != nil{
			return err
		}
		if n < 3 || n < int(buf[1]) + 3{
			return errors.New("Data not correct.")
		}
		username_len := int(buf[1])
		username := buf[2:2 + username_len]
		password := buf[3 + username_len:n]
		if bytes.Equal(username, config.username) && bytes.Equal(password, config.password){
			conn.Write([]byte{0x01, 0x00})
			return nil
		}
		return errors.New("Invalid username or password.")
	}
	return nil
}

func getAddr(conn *net.TCPConn) ([]byte, error){
	buf := make([]byte, 259)
	n, err := conn.Read(buf)
	if err != nil || n < 7{
		return nil, err
	}
	var dstAddr []byte
	switch buf[3]{
	case 0x01:
		if n < 6 + net.IPv4len{
			return nil, errors.New("Invalid packet.")
		}
		dstAddr = buf[3: 6 + net.IPv4len]
	case 0x03:
		if n < 8 || n < 6 + int(buf[4]){
			return nil, errors.New("Invalid packet.")
		}
		dstAddr = buf[3: 7 + int(buf[4])]
	case 0x04:
		if n < 6 + net.IPv6len{
			return nil, errors.New("Invalid packet.")
		}
		dstAddr = buf[3: 6 + net.IPv6len]
	default:
		return nil, errors.New("Invalid packet.")
	}

	switch buf[1]{
	case 0x01:
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10, 0x10})
	default:
		conn.Write([]byte{0x05, 0x07})
		return nil, errors.New("Unsupported command.")
	}
	return dstAddr, nil
}

func relay(left, right net.Conn) (int64, int64, error) {
	type res struct {
		N   int64
		Err error
	}
	ch := make(chan res)

	go func() {
		n, err := io.Copy(right, left)
		right.SetDeadline(time.Now()) // wake up the other goroutine blocking on right
		left.SetDeadline(time.Now())  // wake up the other goroutine blocking on left
		ch <- res{n, err}
	}()

	n, err := io.Copy(left, right)
	right.SetDeadline(time.Now()) // wake up the other goroutine blocking on right
	left.SetDeadline(time.Now())  // wake up the other goroutine blocking on left
	rs := <-ch

	if err == nil {
		err = rs.Err
	}
	return n, rs.N, err
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

func LoadUserConfig(config_file string, verbose bool) (Config, error){
	user_config := userConfig{Maxfail:default_Maxfail, Recovertime:default_Recovertime, Listen: default_Listen}
	config := Config{verbose: verbose}
	data, err := ioutil.ReadFile(config_file)
	if err != nil{
		return config, err
	}
	if err := json.Unmarshal(data, &user_config); err != nil{
		return config, err
	}
	if user_config.Listen == "" || user_config.Port == 0{
		return config, errors.New("Cannot load config.")
	}
	config.listenAddr = net.TCPAddr{IP: net.ParseIP(user_config.Listen), Port: user_config.Port}
	config.auth, config.username, config.password = user_config.Auth, []byte(user_config.Username), []byte(user_config.Password)
	config.servers = make([]Server, 0, len(config.servers))
	for _, st := range user_config.Servers{
		s, err := makeServer(st)
		if err != nil{
			continue
		}
		config.servers = append(config.servers, s)
	}
	config.scheduler = Scheduler{}
	config.scheduler.init(len(config.servers), user_config.Maxfail, channel_buffer_size, user_config.Recovertime, verbose)
	return config, nil
}

func makeServer(s string) (Server, error){
	addr, cipher, password, err := parseURL(s)
	if err != nil{
		return Server{}, err
	}
	ciph, err := core.PickCipher(cipher, []byte{}, password)
	if err != nil{
		return Server{}, err
	}
	return Server{s,ciph, addr}, nil
}

func main(){
	var config_file string
	var verbose bool
	flag.BoolVar(&verbose, "v", false, "verbose mode")
	flag.StringVar(&config_file, "c","config.json", "config file path")


	c, err := LoadUserConfig(config_file, verbose)
	if err != nil{
		log.Println("Error!", err)
		return
	}
	c.StartServer()
}