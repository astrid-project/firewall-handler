package main

import (
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	k8sfirewall "github.com/SunSince90/polycube/src/components/k8s/utils/k8sfirewall"
)

func Parse(graph *NFV) map[string]k8sfirewall.Chain {
	rulesMap := map[string]k8sfirewall.Chain{}

	for _, node := range graph.Graphs[0].Nodes {
		if strings.ToLower(node.FunctionalType) == "firewall" {
			ip := node.Neighbour[0].Name

			if len(node.Configuration.Firewall.Elements) < 1 {
				log.Warningln("No firewall configuration for pod with ip", ip)
			}

			//	parse the rules
			rules := parseRules(node.Configuration.Firewall.Elements)
			chain := k8sfirewall.Chain{
				Name:     "ingress", //TODO: this has to be defined on the low level configuration
				Default_: parseAction(node.Configuration.Firewall.DefaultAction),
				Rule:     rules,
			}

			rulesMap[ip] = chain
		}
	}

	return rulesMap
}

func parseRules(elements []Elements) []k8sfirewall.ChainRule {
	//	allocate statically
	rules := make([]k8sfirewall.ChainRule, len(elements))

	for i := 0; i < len(elements); i++ {
		rules[i] = k8sfirewall.ChainRule{
			Id:          int32(i),
			Src:         parseIP(elements[i].Source),
			Dst:         parseIP(elements[i].Destination),
			Sport:       parsePort(elements[i].SrcPort),
			Dport:       parsePort(elements[i].DstPort),
			Action:      parseAction(elements[i].Action),
			Description: "astrid.io/policyname=foo",
		}
	}

	return rules
}

func parseIP(ip string) string {
	if ip == "-1.-1.-1.-1" {
		return ""
	}

	cidrSuffix := "/32"
	splitIP := strings.Split(ip, ".")
	if splitIP[3] == "-1" {
		splitIP[3] = "0"
		cidrSuffix = "/24"
	}
	if splitIP[2] == "-1" {
		splitIP[2] = "0"
		cidrSuffix = "/16"
	}
	if splitIP[1] == "-1" {
		splitIP[1] = "0"
		cidrSuffix = "/8"
	}

	ip = strings.Join(splitIP, ".")
	return ip + cidrSuffix
}

func parseAction(action string) string {
	if strings.ToLower(action) == "allow" {
		return "forward"
	}

	//	For any other
	return "drop"
}

func parseProtocol(proto string) string {
	switch strings.ToLower(proto) {
	case "any":
		return ""
	case "tcp":
		return "tcp"
	case "udp":
		return "udp"
	case "icmp":
		return "icmp"
	}

	//	any other value
	return ""
}

func parsePort(port string) int32 {
	if port == "*" {
		return 0
	}

	//	try to cast it
	p, err := strconv.ParseInt(port, 10, 32)
	if err != nil {
		//	This should return an error, actually
		return 0
	}

	//	cast it again to an int32
	return int32(p)
}
