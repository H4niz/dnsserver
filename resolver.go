package main

import (
	"fmt"
	"log"
	"github.com/miekg/dns"
	"time"
	"os"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Server struct {
		Host string `yaml: "host"`
		Port string `yaml: "port"`
		NetProtocol string `yaml: "netprotocol`
		UDPSize int `yaml: "udpsize"`
	} `yaml: "server"`
}

var cfg Config
type dnsHandler struct{}

func Configparser() {
	f, err := os.Open("./configuration.yml")
	if err != nil {
		log.Printf("[Configparser] - Open configuration file error: %s\n", err.Error())
	}
	defer f.Close()

	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&cfg)
	if err != nil {
		log.Printf("[Configparser] - Decode configuration error: %s\n", err.Error())
	}
}

func bitDomResolve(domain string, qtype uint16) []dns.RR {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = true
	answers := []dns.RR{}
	c := &dns.Client{Timeout: 5 * time.Second}
	
	in, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil {
		log.Println(err)
		return answers
	}

	for _, ans := range in.Answer {
		log.Println(ans)
		answers = append(answers, ans)
	}
	return answers
}

func (h *dnsHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg){
	msg := new (dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	for _, question := range r.Question	{
		log.Printf("[ServeDNS] - Received query: %s\n", question.Name)
		answer := bitDomResolve(question.Name, question.Qtype)
		msg.Answer = append(msg.Answer, answer...)
	}

	w.WriteMsg(msg)
}

func runDNSServer()	{
	handler := new(dnsHandler)
	dnsserver := fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port)
	log.Printf("Listen on host: %s:%s", cfg.Server.Host, cfg.Server.Port)
	server := &dns.Server{
		Handler:	handler,
		Addr:		dnsserver,
		Net:		cfg.Server.NetProtocol,
		UDPSize:	cfg.Server.UDPSize,
		ReusePort:	true,
	}

	log.Printf("[runDNSServer] - Starting DNS server on %s\n", dnsserver)

	err := server.ListenAndServe()
	if err != nil {
		log.Printf("[runDNSServer] - Failed to start server: %s\n", err.Error())
	}
}

func main() {
	Configparser()
	// log.Println(cfg.Server.UDPSize, cfg.Server.NetProtocol)
	curtime := time.Now()
	file_log_name := fmt.Sprintf("log_%d-%d-%d.log", curtime.Day(), curtime.Month(), curtime.Year())

	f, err := os.OpenFile(file_log_name, os.O_RDWR | os.O_CREATE | os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("[main] - error opening file: %v", err)
	}
	defer f.Close()

	log.SetOutput(f)
	log.Println("\n\n===== New Session =====\n")

	runDNSServer()
}
