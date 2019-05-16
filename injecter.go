package main

import (
	"bytes"
	"encoding/json"
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
			apply(ip, chain.Name)
		}(currentIP, currentChain)
	}
	waiter.Wait()
}

func reset(ip string) {
	endPoint := "http://" + ip + ":9000/polycube/v1/firewall/fw/chain/ingress/rule"
	req, err := http.NewRequest("DELETE", endPoint, nil)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	_, err = client.Do(req)
	if err != nil {
		log.Errorln("Error while trying to send request:", err)
	}

}

func push(ip string, rules []k8sfirewall.ChainRule) {
	if len(rules) > 0 {
		reset(ip)
	}
	for _, rule := range rules {
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
			log.Infoln("Pushed rule in", ip)
		}
	}
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
