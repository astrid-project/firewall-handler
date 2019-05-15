package main

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func homePage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Success")
	fmt.Println("\t\t--- HIT ---")

	body, err := ioutil.ReadAll(r.Body)
	//body, err := ioutil.ReadFile("./conf.xml")
	if err != nil {
		fmt.Println("Error in getting body:", err)
	}
	g := &NFV{}

	err = xml.Unmarshal([]byte(body), &g)
	if err != nil {
		fmt.Println("error in unmarshalling xml", err)
		return
	}

	//	parse...
	chains := Parse(g)

	//	... and inject
	Inject(chains)
}

func handleRequests() {
	http.HandleFunc("/", homePage)
	fmt.Println("Serving requests on localhost:8083")
	log.Fatal(http.ListenAndServe(":8083", nil))
}

func main() {
	homePage(nil, nil)
	handleRequests()
}
