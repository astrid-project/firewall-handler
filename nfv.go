package main

type NFV struct {
	Graphs            []Graph              `xml:"graphs"`
	Constraints       Constraints          `xml:"Constraints"`
	PropertyDefintion []PropertyDefinition `xml:"PropertyDefinition>Property"`
}

type Graph struct {
	Id    int32  `xml:"id,attr"`
	Nodes []Node `xml:"graph>node"`
}
type Node struct {
	Name           string        `xml:"name,attr"`
	FunctionalType string        `xml:"functional_type,attr"`
	Neighbour      []Neighbour   `xml:"neighbour"`
	Configuration  Configuration `xml:"configuration"`
}
type Neighbour struct {
	Name string `xml:"name,attr"`
}
type Configuration struct {
	Name        string    `xml:"name,attr"`
	Description string    `xml:"description,attr"`
	WebServer   WebServer `xml:"webserver"`
	Firewall    Firewall  `xml:"firewall"`
}
type WebServer struct {
	Name string `xml:"name"`
}
type Firewall struct {
	Elements      []Elements `xml:"elements"`
	DefaultAction string     `xml:"defaultAction,attr"`
}
type Elements struct {
	Action      string `xml:"action"`
	Source      string `xml:"source"`
	Destination string `xml:"destination"`
	Protocol    string `xml:"protocol"`
	SrcPort     string `xml:"src_port"`
	DstPort     string `xml:"dst_port"`
}
type Constraints struct {
	NodeConstraints NodeConstraints `xml:"NodeConstraints"`
}
type NodeConstraints struct {
	NodeMetrics []NodeMetric `xml:"NodeMetrics"`
}
type NodeMetric struct {
	Node    string `xml:"node,attr"`
	Options bool   `xml:"optional"`
}
type PropertyDefinition struct {
	Name  string `xml:"name,attr"`
	Graph string `xml:"graph,attr"`
	Src   string `xml:"src,attr"`
	Dst   string `xml:"dst,attr"`
	IsSat bool   `xml:"isSat,attr"`
}
