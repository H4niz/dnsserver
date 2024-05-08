package main

import (
	"fmt"
	"log"
	"github.com/miekg/dns"
	"time"
	"os"
	"gopkg.in/yaml.v2"

	c "github.com/ostafen/clover/v2"
	"github.com/ostafen/clover/v2/query"
	d "github.com/ostafen/clover/v2/document"
)

type Config struct {
	Server struct {
		Host string `yaml: "host"`
		Port string `yaml: "port"`
		NetProtocol string `yaml: "netprotocol`
		UDPSize int `yaml: "udpsize"`
	} `yaml: "server"`
	Database struct {
		DBName string `yaml: "dbname"`
	} `yaml: "database`
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


type Malicious_Entity struct {
	Entity      string
	Description string
	Date        string
}

type Malicious_Traffic struct {
	DestinationEntry string
	Description      string
	SourceDevices    string
	SourceIP         string
	Status           string
	DateUpdated      string
}

func insert_document(collection_name string, key []string, value []string) (string) {
	db, err := c.Open(cfg.Database.DBName)
	if err != nil {
		log.Fatalf("[insert_document] - error opening file: %v", err)
	}
	defer db.Close()
	isExist, err := db.HasCollection(collection_name)
	if err != nil {
		log.Printf("[insert_document] - check Exist document error! %s", err.Error())
	}
	defer db.Close()

	if !isExist {
		err := db.CreateCollection(collection_name)
		if err != nil {
			log.Printf("[insert_document] - Create new collection error! %s", err.Error())
		}
	}

	doc := d.NewDocument()
	for idx, key := range key {
		doc.Set(key, value[idx])
	}

	docId, err := db.InsertOne(collection_name, doc)
	if err != nil {
		log.Printf("[insert_document] - Insert document error! %s", err.Error())
	}
	log.Printf("[insert_document] - Insert document successfull with id: %s", docId)
	
	// Read db
	docs, err := db.FindAll(query.NewQuery(collection_name))
	if err != nil {
		log.Printf("[insert_document] - Error when findall databases! %s\n", err.Error())
	}
	defer db.Close()
	for _, doc := range docs {
		log.Println(doc)
	}

	db.Close()
	return docId
}

func logMaliciousTraffic(mal_traf Malicious_Traffic) (bool, string)	{
	key_name := []string{
		"DestinationEntry",
		"Description",
		"SourceDevices",
		"SourceIP",
		"Status",
		"DateUpdated",
	}
	values := []string{
		mal_traf.DestinationEntry,
		mal_traf.Description,
		mal_traf.SourceDevices,
		mal_traf.SourceIP,
		mal_traf.Status,
		mal_traf.DateUpdated,
	}

	// fmt.Println(values, key_name)
	insert_document("MaliciousTraffic", key_name, values)
	// if err != nil {
	// 	log.Printf("[logMaliciousTraffic] - Error when insert data: %s\n", err.Error())
	// }

	return true, "Ok"
}

func isBlacklist(ddomain string, w dns.ResponseWriter)	bool {
	db, err := c.Open(cfg.Database.DBName)
	if err != nil {
		log.Fatalf("[isBlacklist] - error opening file: %v", err)
	}
	defer db.Close()

	domain := fmt.Sprint(ddomain[:len(ddomain)-1])

	log.Printf("[isBlacklist] - Check domain: %s\n", domain)
	docs, err := db.FindAll(query.NewQuery("DomainMalicious").Where(query.Field("Domain").Eq(domain)))
	db.Close()
	
	if err != nil {
		log.Printf("[isBlacklist] - Query document error! %s", err.Error())
	}

	// iamkevinfay.com
	if len(docs) > 0 {
		mal_trafic := Malicious_Traffic{}
		for _, doc := range docs {
			form_doc := Malicious_Entity{}
			doc.Unmarshal(form_doc)
			mal_trafic.DestinationEntry = fmt.Sprint(doc.Get("Domain"))
			mal_trafic.Description = fmt.Sprint(doc.Get("Description"))
			mal_trafic.DateUpdated = fmt.Sprint(doc.Get("Date"))
			mal_trafic.SourceIP = fmt.Sprint(w.RemoteAddr())
			mal_trafic.Status = "Blocked"
		}
	
		log.Println(mal_trafic)
		logMaliciousTraffic(mal_trafic)

		return true
	}
	return false
}

func bitDomeResolve(domain string, qtype uint16) []dns.RR {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = true
	answers := []dns.RR{}
	c := &dns.Client{Timeout: 5 * time.Second}
	
	in, _, err := c.Exchange(m, "1.1.1.1:53")
	if err != nil {
		log.Println("[bitdomeResolve] - Error when resolve domain: %s - Error: ", domain, err.Error())
		return answers
	}

	for _, ans := range in.Answer {
		// log.Println(ans)
		answers = append(answers, ans)
	}
	return answers
}

func (h *dnsHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg){
	msg := new (dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	for _, question := range r.Question	{
		answer := []dns.RR{}
		log.Printf("[ServeDNS] - Received query: %s\t%d\n", question.Name, question.Qtype)
		domainname := question.Name
		
		if isBlacklist(fmt.Sprint(question.Name), w) {
			log.Printf("[ServeDNS] - Domain %s is blocked from %s\n", domainname, w.RemoteAddr())
		} else {
			answer = bitDomeResolve(question.Name, question.Qtype)
			msg.Answer = append(msg.Answer, answer...)
		}
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
