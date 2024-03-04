package main

import (
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
)

/*
	###
	# Main Function
	###
*/
/*	########################################################################################################	*/
func main() {
	var nessusPtr, vlunPtr string
	flag.StringVar(&nessusPtr, "n", "", "Nessus XML file to parse")
	flag.StringVar(&vlunPtr, "v", "", "Parse a single vulnerbility or issue for the Nessus XML file")
	// Parse all the flags
	flag.Usage = func() {
		flagSet := flag.CommandLine
		shorthand := []string{"n", "v"}
		fmt.Printf("\n    	The following syntax is for operational flags:\n\t---------------------------------------------------\n")
		for _, name := range shorthand {
			flag := flagSet.Lookup(name)
			fmt.Printf("\t-%s\t | %s\n", flag.Name, flag.Usage)
		}
		fmt.Printf("\n\n    	The following shows examples of tool usage:\n\t---------------------------------------------------\n")
		fmt.Printf("    	./gress -n my_scan_lfi55d.nessus\n")
		fmt.Println(`    	./gress -n my_scan_lfi55d.nessus -v "SSL Weak Cipher Suites Supported"`)
		fmt.Println(`    	./gress -n my_scan_lfi55d.nessus | cut -f 4- -d "," | sort -u | xargs -i ./gress -n my_scan_lfi55d.nessus -v {}`)
		fmt.Printf("\n\n")
	}
	flag.Parse()

	// If no file presented to the application, print the banner message
	if nessusPtr == "" {
		flagbanner()
		flag.Usage()
		return
	}
	xmlfilename, err := os.Open(nessusPtr)
	xmlByte, _ := io.ReadAll(xmlfilename)
	parse, err := Parse(xmlByte)
	if err != nil {
		log.Fatal(err)
	}
	var collection []Issue
	for _, ip := range parse.Report.ReportHosts {
		for _, ritems := range ip.ReportItems {
			a := Issue{
				Ip:       ip.Name,
				Port:     ritems.Port,
				CVSScore: ritems.CVSSBaseScore,
				Name:     fmt.Sprintf(strings.Replace(ritems.PluginName, "'", "", -1)),
			}
			collection = append(collection, a)
		}
	}

	// Sort the output by domain
	sort.Sort(ByVulnName(collection))
	if len(vlunPtr) > 0 {
		var sockets []IPort
		for _, i := range collection {
			if i.Name == vlunPtr {
				a := IPort{Ip: i.Ip, Port: i.Port}
				sockets = append(sockets, a)
			}
		}
		sort.Sort(ByIP(sockets))
		fmt.Printf("%s\n---------------------------------------------------\n", vlunPtr)
		for _, i := range sockets {
			fmt.Printf("%s,%d\n", i.Ip, i.Port)
		}
		fmt.Printf("\n")
	} else {
		for _, i := range collection {
			fmt.Printf("%s,%d,%1.1f,%s\n", i.Ip, i.Port, float64(i.CVSScore), i.Name)
		}
	}
}

/*	########################################################################################################	*/
/*
	###
	# Functions used inside the main loop
	###
*/
/* Functions used inside the main loop */

/* ## Raise software banner includeing version ## */
func flagbanner() {
	fmt.Printf("\n\tGRep-able nESSus (gress)")
	fmt.Printf("\n\t---------------------------------------------------\n\tParse Nessus into a Bash Grep-able syntax\n\t---------------------------------------------------\n")
}

/* ## Sort Slices By Nessus Vuln Title ## */
func (a ByVulnName) Len() int {
	return len(a)
}

func (a ByVulnName) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a ByVulnName) Less(i, j int) bool {
	return a[i].Name < a[j].Name
}

/* ## Sort Slices By IP address ## */
func (a ByIP) Len() int {
	return len(a)
}

func (a ByIP) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a ByIP) Less(i, j int) bool {
	return a[i].Ip < a[j].Ip
}

/* ## Parse Nessus File into Datastructure below ## */
/* ## https://github.com/lair-framework/go-nessus/blob/master/nessus.go ## */
func Parse(content []byte) (*NessusData, error) {
	r := &NessusData{}
	err := xml.Unmarshal(content, r)
	if err != nil {
		return r, err
	}
	return r, nil
}

/*	########################################################################################################	*/
/*
	###
	# Datagrams & Structures
	###
*/

/* ## Collection slice to be sorted ## */
type Issue struct {
	Ip       string
	Port     int
	CVSScore float64
	Name     string
}

// For sorting by Vuln Name (title of the issue)
type ByVulnName []Issue

// Collection slice to be sorted
type IPort struct {
	Ip   string
	Port int
}

// For sorting by IP
type ByIP []IPort

/* ## NessusData contains a nessus report. Please see URL below, this was the orginal data structure used/incorperated into this script ## */
/* ## https://github.com/lair-framework/go-nessus/blob/master/nessus.go ## */
type NessusData struct {
	Report Report `xml:"Report"`
}

/* ## Report has a name and contains all the host details. ## */
type Report struct {
	Name        string       `xml:"name,attr"`
	ReportHosts []ReportHost `xml:"ReportHost"`
}

/* ## ReportHost containts the hostname or ip address for the host and all vulnerability and service information.  ## */
type ReportHost struct {
	Name           string         `xml:"name,attr"`
	HostProperties HostProperties `xml:"HostProperties"`
	ReportItems    []ReportItem   `xml:"ReportItem"`
}

/* ## HostProperties are tags filled with likely useless information. ## */
type HostProperties struct {
	Tags []Tag `xml:"tag"`
}

/* ## Tag is used to split the tag into name and the tag content. ## */
type Tag struct {
	Name string `xml:"name,attr"`
	Data string `xml:",chardata"`
}

/* ## ReportItem is vulnerability plugin output. ## */
type ReportItem struct {
	Port                       int      `xml:"port,attr"`
	SvcName                    string   `xml:"svc_name,attr"`
	Protocol                   string   `xml:"protocol,attr"`
	Severity                   int      `xml:"severity,attr"`
	PluginID                   string   `xml:"pluginID,attr"`
	PluginName                 string   `xml:"pluginName,attr"`
	PluginFamily               string   `xml:"pluginFamily,attr"`
	PluginType                 string   `xml:"plugin_type,name"`
	PluginVersion              string   `xml:"plugin_version"`
	Fname                      string   `xml:"fname,name"`
	RiskFactor                 string   `xml:"risk_factor,name"`
	Synopsis                   string   `xml:"synopsis,name"`
	Description                string   `xml:"description,name"`
	Solution                   string   `xml:"solution,name"`
	PluginOutput               string   `xml:"plugin_output,name"`
	SeeAlso                    string   `xml:"see_also,name"`
	CVE                        []string `xml:"cve,name"`
	BID                        []string `xml:"bid,name"`
	XREF                       []string `xml:"xref,name"`
	PluginModificationDate     string   `xml:"plugin_modification_date,name"`
	PluginPublicationDate      string   `xml:"plugin_publication_date,name"`
	VulnPublicationDate        string   `xml:"vuln_publication_date,name"`
	ExploitabilityEase         string   `xml:"exploitability_ease,name"`
	ExploitAvailable           bool     `xml:"exploit_available,name"`
	ExploitFrameworkCanvas     bool     `xml:"exploit_framework_canvas,name"`
	ExploitFrameworkMetasploit bool     `xml:"exploit_framework_metasploit,name"`
	ExploitFrameworkCore       bool     `xml:"exploit_framework_core,name"`
	MetasploitName             string   `xml:"metasploit_name,name"`
	CanvasPackage              string   `xml:"canvas_package,name"`
	CoreName                   string   `xml:"core_name,name"`
	CVSSVector                 string   `xml:"cvss_vector,name"`
	CVSSBaseScore              float64  `xml:"cvss_base_score,name"`
	CVSSTemporalScore          string   `xml:"cvss_temporal_score,name"`
	ComplianceResult           string   `xml:"cm:compliance-result,name"`
	ComplianceActualValue      string   `xml:"cm:compliance-actual-value,name"`
	ComplianceCheckID          string   `xml:"cm:compliance-check-id,name"`
	ComplianceAuditFile        string   `xml:"cm:compliance-audit-file,name"`
	ComplianceCheckValue       string   `xml:"cm:compliance-check-name,name"`
}
