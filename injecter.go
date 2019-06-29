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
			push(ip, chain.Rule)
			apply(ip, "ingress")
			apply(ip, "egress")
		}(currentIP, currentChain)
	}
	waiter.Wait()
}

func reset(ip string) {
	marshal := func(rule k8sfirewall.ChainRule) ([]byte, error) {
		data, err := json.MarshalIndent(&rule, "", "   ")
		if err != nil {
			log.Errorln("Cannot marshal to json:", err)
			return nil, err
		}
		return data, nil
	}

	ingress := func() {
		//	Reset ingress
		endPoint := "http://" + ip + ":9000/polycube/v1/firewall/fw/chain/ingress/rule"
		req, err := http.NewRequest("DELETE", endPoint, nil)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		_, err = client.Do(req)
		if err != nil {
			log.Errorln("Error while trying to send request:", err)
		}

		//	Readd rule to allow polycube
		endPoint = "http://" + ip + ":9000/polycube/v1/firewall/fw/chain/ingress/append/"
		rule := k8sfirewall.ChainRule{
			Action: "forward",
			Dst:    ip,
			Dport:  9000,
		}
		data, err := marshal(rule)
		if err == nil {
			req, err := http.NewRequest("POST", endPoint, bytes.NewBuffer(data))
			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{}
			_, err = client.Do(req)
			if err != nil {
				log.Errorln("Error while trying to send request:", err)
			}
		}
	}

	egress := func() {
		//	Reset egress
		endPoint := "http://" + ip + ":9000/polycube/v1/firewall/fw/chain/egress/rule"
		req, err := http.NewRequest("DELETE", endPoint, nil)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		_, err = client.Do(req)
		if err != nil {
			log.Errorln("Error while trying to send request:", err)
		}

		//	Readd rule to allow polycube
		endPoint = "http://" + ip + ":9000/polycube/v1/firewall/fw/chain/egress/append/"
		rule := k8sfirewall.ChainRule{
			Action: "forward",
			Src:    ip,
			Sport:  9000,
		}
		data, err := marshal(rule)
		if err == nil {
			req, err := http.NewRequest("POST", endPoint, bytes.NewBuffer(data))
			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{}
			_, err = client.Do(req)
			if err != nil {
				log.Errorln("Error while trying to send request:", err)
			}
		}
	}

	ingress()
	egress()
}

func push(ip string, rules []k8sfirewall.ChainRule) {
	if len(rules) > 0 {
		reset(ip)
	}
	for _, rule := range rules {
		ingressRule := rule

		//	Reformat for egress
		egressRule := rule
		egressRule.Dst = rule.Src
		egressRule.Src = rule.Dst
		egressRule.Sport = rule.Dport
		egressRule.Dport = rule.Sport

		//	Egress
		egress := func(er k8sfirewall.ChainRule) {
			endPoint := "http://" + ip + ":9000/polycube/v1/firewall/fw/chain/egress/append/"
			data, err := marshal(rule)
			if err == nil {
				req, err := http.NewRequest("POST", endPoint, bytes.NewBuffer(data))
				req.Header.Set("Content-Type", "application/json")

				client := &http.Client{}
				_, err = client.Do(req)
				if err != nil {
					log.Errorln("Error while trying to send request:", err)
				}
			}
		}

		//	Ingress
		ingress := func(ir k8sfirewall.ChainRule) {
			endPoint := "http://" + ip + ":9000/polycube/v1/firewall/fw/chain/ingress/append/"
			data, err := marshal(rule)
			if err == nil {
				req, err := http.NewRequest("POST", endPoint, bytes.NewBuffer(data))
				req.Header.Set("Content-Type", "application/json")

				client := &http.Client{}
				_, err = client.Do(req)
				if err != nil {
					log.Errorln("Error while trying to send request:", err)
				}
			}
		}

		egress(egressRule)
		ingress(ingressRule)

		log.Infoln("Pushed the following policy in", ip, ":")

		ingressText := formatText(ingressRule, "ingress")
		egressText := formatText(egressRule, "egress")
		log.Println(ingressText)
		log.Println(egressText)
	}
}

func formatText(rule k8sfirewall.ChainRule, direction string) string {
	ingress := func() string {
		ingressText := "\t FROM "

		if len(rule.Src) > 0 {
			ingressText += rule.Src
		} else {
			ingressText += "ANY"
		}

		ingressText += " "
		ingressText += "TO: " + rule.Dst

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
			egressText += "ANY"
		}

		egressText += " "
		egressText += "TO: " + rule.Dst

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
		log.Errorln("Error while trying to apply rules:", err)
	}

	return true, nil
}
