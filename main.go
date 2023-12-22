package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lmittmann/tint"
	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
	"github.com/miekg/dns"
)

// CommaSeparatedListFlag is a custom flags that satisfy the Value interface (https://pkg.go.dev/flag#Value)
type CommaSeparatedListFlag struct {
	listStr []string
}

func (i *CommaSeparatedListFlag) String() string {
	return strings.Join(i.listStr, ", ")
}

func (i *CommaSeparatedListFlag) Set(value string) error {
	s := strings.Split(value, ",")
	for i := range s {
		s[i] = dns.Fqdn(strings.ToLower(strings.TrimSpace(s[i])))
	}
	i.listStr = append(i.listStr, s...)
	return nil
}

func isFlagSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

var (
	fakeDomains CommaSeparatedListFlag
	port        = flag.Int("port", 53, "Port number to use.")

	fakeIpStr    = flag.String("fakeip", "", "IP address to use for matching DNS queries. If you use this parameter without specifying domain names, then all 'A' queries will be spoofed.")
	fakeIpv6Str  = flag.String("fakeipv6", "", "IPv6 address to use for matching DNS queries. If you use this parameter without specifying domain names, then all 'AAAA' queries will be spoofed.")
	fakeMailStr  = flag.String("fakemail", "", "MX name to use for matching DNS queries. If you use this parameter without specifying domain names, then all 'MX' queries will be spoofed.")
	fakeAliasStr = flag.String("fakealias", "", "CNAME name to use for matching DNS queries. If you use this parameter without specifying domain names, then all 'CNAME' queries will be spoofed.")
	fakeNSStr    = flag.String("fakens", "", "NS name to use for matching DNS queries. If you use this parameter without specifying domain names, then all 'NS' queries will be spoofed.")
	logFile      = flag.String("logfile", "", "Specify a log file to record all activity.")

	nameserver = flag.String("nameserver", "8.8.8.8", "Alternative DNS server to use with proxied requests.")
)

func main() {
	flag.Var(&fakeDomains, "fakedomains", "A comma separated list of domain names which will be resolved to FAKE values specified in the the above parameters. All other domain names will be resolved to their true values.")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	var w *os.File = os.Stdout
	var err error
	if *logFile != "" {
		w, err = os.OpenFile(*logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			slog.Error("OpenFile", slog.String("err", err.Error()))
			os.Exit(1)
		}
	}
	// set global logger with custom options
	slog.SetDefault(slog.New(
		tint.NewHandler(colorable.NewColorable(w), &tint.Options{
			Level:      slog.LevelDebug,
			TimeFormat: time.DateTime,
			NoColor:    !isatty.IsTerminal(w.Fd()),
		}),
	))

	fakeDomainsLength := len(fakeDomains.listStr)
	// qtypeToDomain['A']['go.dev'] = fakeIPStr
	var qtypeToDomain map[uint16]map[string]string = make(map[uint16]map[string]string)

	if isFlagSet("fakeip") {
		qtypeToDomain[dns.TypeA] = make(map[string]string)
		if net.ParseIP(*fakeIpStr) == nil {
			slog.Error("Invalid fake IP", slog.String("fakeip", *fakeIpStr))
			os.Exit(1)
		}
		qtypeToDomain[dns.TypeA]["DEFAULT"] = *fakeIpStr
		if fakeDomainsLength == 0 {
			slog.Info("Handling 'A' requests", slog.String("ip", *fakeIpStr))
		}
	}
	if isFlagSet("fakeipv6") {
		qtypeToDomain[dns.TypeAAAA] = make(map[string]string)
		if net.ParseIP(*fakeIpv6Str) == nil {
			slog.Error("Invalid fake IPv6", slog.String("fakeipv6", *fakeIpv6Str))
			os.Exit(1)
		}
		qtypeToDomain[dns.TypeAAAA]["DEFAULT"] = *fakeIpv6Str
		if fakeDomainsLength == 0 {
			slog.Info("Handling 'AAAA' requests", slog.String("ip", *fakeIpv6Str))
		}
	}
	if isFlagSet("fakemail") {
		qtypeToDomain[dns.TypeMX] = make(map[string]string)
		if _, ok := dns.IsDomainName(*fakeMailStr); !ok {
			slog.Error("Invalid fake mail server", slog.String("domainName", *fakeMailStr))
			os.Exit(1)
		}
		qtypeToDomain[dns.TypeMX]["DEFAULT"] = *fakeMailStr
		if fakeDomainsLength == 0 {
			slog.Info("Handling 'MX' requests", slog.String("domainName", *fakeMailStr))
		}
	}
	if isFlagSet("fakealias") {
		qtypeToDomain[dns.TypeCNAME] = make(map[string]string)
		if _, ok := dns.IsDomainName(*fakeAliasStr); !ok {
			slog.Error("Invalid fake alias server", slog.String("domainName", *fakeAliasStr))
			os.Exit(1)
		}
		qtypeToDomain[dns.TypeCNAME]["DEFAULT"] = *fakeAliasStr
		if fakeDomainsLength == 0 {
			slog.Info("Handling 'CNAME' requests", slog.String("domainName", *fakeAliasStr))
		}
	}
	if isFlagSet("fakens") {
		qtypeToDomain[dns.TypeNS] = make(map[string]string)
		if _, ok := dns.IsDomainName(*fakeNSStr); !ok {
			slog.Error("Invalid fake NS server", slog.String("domainName", *fakeNSStr))
			os.Exit(1)
		}
		qtypeToDomain[dns.TypeNS]["DEFAULT"] = *fakeNSStr
		if fakeDomainsLength == 0 {
			slog.Info("Handling 'NS' requests", slog.String("domainName", *fakeNSStr))
		}
	}

	for k, v := range qtypeToDomain {
		for _, domain := range fakeDomains.listStr {
			switch k {
			case dns.TypeA:
				v[domain] = *fakeIpStr
				slog.Info("Handling replies", slog.String("from", domain), slog.String("type", dns.TypeToString[dns.TypeA]), slog.String("to", *fakeIpStr))
			case dns.TypeAAAA:
				v[domain] = *fakeIpv6Str
				slog.Info("Handling replies", slog.String("from", domain), slog.String("type", dns.TypeToString[dns.TypeAAAA]), slog.String("to", *fakeIpv6Str))
			case dns.TypeMX:
				v[domain] = *fakeMailStr
				slog.Info("Handling replies", slog.String("from", domain), slog.String("type", dns.TypeToString[dns.TypeMX]), slog.String("to", *fakeMailStr))
			case dns.TypeCNAME:
				v[domain] = *fakeAliasStr
				slog.Info("Handling replies", slog.String("from", domain), slog.String("type", dns.TypeToString[dns.TypeCNAME]), slog.String("to", *fakeAliasStr))
			case dns.TypeNS:
				v[domain] = *fakeNSStr
				slog.Info("Handling replies", slog.String("from", domain), slog.String("type", dns.TypeToString[dns.TypeNS]), slog.String("to", *fakeNSStr))
			}
		}
	}

	if fakeDomainsLength > 0 && len(qtypeToDomain) == 0 {
		slog.Error("Nothing to FAKE but you specified fakedomains...", slog.String("fakedomains", fakeDomains.String()))
		os.Exit(1)
	}

	if len(qtypeToDomain) == 0 {
		slog.Info("No parameters were specified. Running in full proxy mode.")
	}

	dns.HandleFunc(".", func(w dns.ResponseWriter, m *dns.Msg) {
		var err error

		response := new(dns.Msg)
		response.SetReply(m)
		for _, q := range m.Question {
			// to check if we need to fake the response or proxy the request to a real DNS server.
			domainsToFake, isQtypeFaked := qtypeToDomain[q.Qtype]
			fakeRecord, isDomainFaked := domainsToFake[q.Name]
			if isQtypeFaked && isDomainFaked {
				// indicate that our server is authoritative for the zone.
				response.Authoritative = true
				fakeResponse(response, q, fakeRecord)
			} else if isQtypeFaked && fakeDomainsLength == 0 {
				response.Authoritative = true
				fakeResponse(response, q, domainsToFake["DEFAULT"])
			} else {
				slog.Info("Proxying request for", slog.String("domain", q.Name), slog.String("type", dns.TypeToString[q.Qtype]))
				response, err = proxyRequest(m, *nameserver)
				if err != nil {
					slog.Error("Error proxying the request", slog.String("err", err.Error()))
				}
			}
		}

		err = w.WriteMsg(response)
		if err != nil {
			slog.Error("Error writing response to the client", slog.String("err", err.Error()))
		}
	})

	slog.Info("Listening on", slog.Int("port", *port))
	srv := &dns.Server{Addr: net.JoinHostPort("", strconv.Itoa(*port)), Net: "udp"}
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("Failed to set udp listener", slog.String("err", err.Error()))
		os.Exit(1)
	}
}

func proxyRequest(m *dns.Msg, nameserver string) (*dns.Msg, error) {
	return dns.Exchange(m, net.JoinHostPort(nameserver, "53"))
}

func fakeResponse(response *dns.Msg, q dns.Question, fakeRecord string) {
	slog.Info("Creating a fake Response", slog.String("domain", q.Name), slog.String("type", dns.TypeToString[q.Qtype]))
	switch q.Qtype {
	case dns.TypeA:
		response.Answer = append(response.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeA,
				Ttl:    3600,
				Class:  q.Qclass,
			},
			A: net.ParseIP(fakeRecord),
		})
	case dns.TypeAAAA:
		response.Answer = append(response.Answer, &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeAAAA,
				Ttl:    3600,
				Class:  q.Qclass,
			},
			AAAA: net.ParseIP(fakeRecord),
		})
	case dns.TypeMX:
		response.Answer = append(response.Answer, &dns.MX{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeMX,
				Ttl:    3600,
				Class:  q.Qclass,
			},
			Mx: dns.Fqdn(fakeRecord),
		})
	case dns.TypeNS:
		response.Answer = append(response.Answer, &dns.NS{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeNS,
				Ttl:    3600,
				Class:  q.Qclass,
			},
			Ns: dns.Fqdn(fakeRecord),
		})
	case dns.TypeCNAME:
		response.Answer = append(response.Answer, &dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeCNAME,
				Ttl:    3600,
				Class:  q.Qclass,
			},
			Target: dns.Fqdn(fakeRecord),
		})
	default:
		slog.Warn("This qtype is not supported right now", slog.String("qtype", dns.TypeToString[q.Qtype]))
	}
}
