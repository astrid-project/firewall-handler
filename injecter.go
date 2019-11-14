package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	k8sfirewall "github.com/SunSince90/polycube/src/components/k8s/utils/k8sfirewall"
	log "github.com/sirupsen/logrus"
)

func Inject(chains map[string]k8sfirewall.Chain) {
	var waiter sync.WaitGroup
	waiter.Add(len(chains))
	for currentIP, currentChain := range chains {
		go func(ip string, chain k8sfirewall.Chain) {
			defer waiter.Done()
			if alive(ip) {
				push(ip, chain.Rule)
				apply(ip, "ingress")
				apply(ip, "egress")
			}
		}(currentIP, currentChain)
	}
	waiter.Wait()
	fmt.Println("\t\t--- END ---")
}

func alive(ip string) bool {
	endPoint := "http://" + ip + ":9000/polycube/v1/firewall/fw/"
	req, err := http.NewRequest("GET", endPoint, nil)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	_, err = client.Do(req)
	if err != nil {
		log.Errorf("Pod with ip %s not found (is it dying?)", ip)
		return false
	}

	return true
}

func reset(ip string) {

	ingress := func() {
		for i := 1; i < 50; i++ {

			//	Reset ingress
			endPoint := "http://" + ip + ":9000/polycube/v1/firewall/fw/chain/ingress/rule/1"
			req, err := http.NewRequest("DELETE", endPoint, nil)
			req.Header.Set("Content-Type", "application/json")
			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				log.Errorln("Error while trying to send request:", err, "(the pod might be TERMINATING.)")
				return
			}

			if resp.StatusCode == 409 {
				break
			}
		}
	}

	egress := func() {
		//	Reset egress
		for i := 1; i < 50; i++ {
			//	Reset ingress
			endPoint := "http://" + ip + ":9000/polycube/v1/firewall/fw/chain/egress/rule/1"
			req, err := http.NewRequest("DELETE", endPoint, nil)
			req.Header.Set("Content-Type", "application/json")
			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				log.Errorln("Error while trying to send request:", err, "(the pod might be TERMINATING.)")
				return
			}

			if resp.StatusCode == 409 {
				break
			}
		}
	}

	ingress()
	egress()
}

func buildConnectionRules(_ip string, rule k8sfirewall.ChainRule) ([]k8sfirewall.ChainRule, []k8sfirewall.ChainRule) {
	ip := _ip + "/32"
	forwardTemplate := func() ([]k8sfirewall.ChainRule, []k8sfirewall.ChainRule) {
		in := []k8sfirewall.ChainRule{
			k8sfirewall.ChainRule{
				Src:       rule.Src,
				Dst:       rule.Dst,
				Sport:     rule.Sport,
				Dport:     rule.Dport,
				L4proto:   rule.L4proto,
				Conntrack: "new",
				Action:    rule.Action,
			},
		}
		e := []k8sfirewall.ChainRule{}

		return in, e
	}

	dropTemplate := func(rule k8sfirewall.ChainRule) []k8sfirewall.ChainRule {
		return []k8sfirewall.ChainRule{
			k8sfirewall.ChainRule{
				Src:       rule.Src,
				Dst:       rule.Dst,
				Sport:     rule.Sport,
				Dport:     rule.Dport,
				L4proto:   rule.L4proto,
				Conntrack: "new",
				Action:    rule.Action,
			},
		}
	}

	if rule.Action == "forward" {
		if ip == rule.Src {
			e, in := forwardTemplate()
			return in, e
		}

		if ip == rule.Dst {
			return forwardTemplate()
		}
	}
	if rule.Action == "drop" {
		if ip == rule.Src {
			return []k8sfirewall.ChainRule{}, dropTemplate(rule)
		}

		if ip == rule.Dst {
			return dropTemplate(rule), []k8sfirewall.ChainRule{}
		}
	}

	return []k8sfirewall.ChainRule{}, []k8sfirewall.ChainRule{}
}

func push(ip string, rules []k8sfirewall.ChainRule) {
	if len(rules) > 0 {
		reset(ip)
	}
	for _, rule := range rules {

		ingressRules, egressRules := buildConnectionRules(ip, rule)

		//	Egress
		egress := func(ers []k8sfirewall.ChainRule) {
			endPoint := "http://" + ip + ":9000/polycube/v1/firewall/fw/chain/egress/append/"
			for _, er := range ers {
				data, err := marshal(er)
				if err == nil {
					req, err := http.NewRequest("POST", endPoint, bytes.NewBuffer(data))
					req.Header.Set("Content-Type", "application/json")

					client := &http.Client{}
					_, err = client.Do(req)
					if err != nil {
						log.Errorln("Error while trying to send request:", err, "(the pod might be TERMINATING.)")
						return
					}
				}
			}
		}

		//	Ingress
		ingress := func(irs []k8sfirewall.ChainRule) {
			endPoint := "http://" + ip + ":9000/polycube/v1/firewall/fw/chain/ingress/append/"
			for _, ir := range irs {
				data, err := marshal(ir)
				if err == nil {
					req, err := http.NewRequest("POST", endPoint, bytes.NewBuffer(data))
					req.Header.Set("Content-Type", "application/json")

					client := &http.Client{}
					_, err = client.Do(req)
					if err != nil {
						log.Errorln("Error while trying to send request:", err, "(the pod might be TERMINATING.)")
						return
					}
				}
			}
		}

		egress(egressRules)
		ingress(ingressRules)

		log.Infof("Pushed rules in %s", ip)
	}
}

func formatText(rule k8sfirewall.ChainRule, ip, direction string) string {
	ingress := func() string {
		ingressText := "\t FROM "

		if len(rule.Src) > 0 {
			ingressText += rule.Src
		} else {
			ingressText += "ANY"
		}

		ingressText += " "
		ingressText += "TO: "

		if len(rule.Dst) > 0 {
			ingressText += rule.Dst
		} else {
			ingressText += ip
		}

		if rule.Sport != 0 {
			ingressText += " SOURCE-PORT " + fmt.Sprint(rule.Sport)
		}

		if rule.Dport != 0 {
			ingressText += " DESTINATION-PORT " + fmt.Sprint(rule.Dport)
		}

		ingressText += " ACTION: "
		if rule.Action == "forward" {
			ingressText += " ALLOW"
		} else {
			ingressText += " DENY"
		}

		return ingressText
	}

	egress := func() string {
		egressText := "\t FROM "

		if len(rule.Src) > 0 {
			egressText += rule.Src
		} else {
			egressText += ip
		}

		egressText += " "
		egressText += "TO: "

		if len(rule.Dst) > 0 {
			egressText += rule.Dst
		} else {
			egressText += "ANY"
		}

		if rule.Sport != 0 {
			egressText += " SOURCE-PORT " + fmt.Sprint(rule.Sport)
		}

		if rule.Dport != 0 {
			egressText += " DESTINATION-PORT " + fmt.Sprint(rule.Dport)
		}

		egressText += " ACTION: "
		if rule.Action == "forward" {
			egressText += " ALLOW"
		} else {
			egressText += " DENY"
		}

		return egressText
	}

	if direction == "ingress" {
		return ingress()
	}

	return egress()
}

func marshal(rule k8sfirewall.ChainRule) ([]byte, error) {
	data, err := json.MarshalIndent(&rule, "", "   ")
	if err != nil {
		log.Errorln("Cannot marshal to json:", err)
		return nil, err
	}
	return data, nil
}

func apply(ip, name string) (bool, error) {
	endPoint := "http://" + ip + ":9000/polycube/v1/firewall/fw/chain/" + name + "/apply-rules/"
	req, err := http.NewRequest("POST", endPoint, nil)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}

	_, err = client.Do(req)
	if err != nil {
		log.Errorln("Error while trying to apply rules:", err, "(the pod might be TERMINATING.)")
		return false, nil
	}

	return true, nil
}
