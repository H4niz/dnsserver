# dnsserver
a small dns server by go

### DNS
- Domain Name: A human-readable name that represents an IP address, such as example.com.

- Resource Record (RR): A DNS record that contains information about a domain name, including its IP address, mail server, and more.

- Name Server: A server that stores DNS records and answers DNS queries.

- Resolver: A DNS client that sends queries and receives responses from name servers.

- Zone: A segment of the DNS namespace managed by a particular name server.

### Requirement
Using Go DNS package: github.com/miekg/dns


### IPTables
A rule to force DNS query to local DNS Server

`iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to 127.0.0.1:53`