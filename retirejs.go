package main

import (
	"fmt"
	"regexp"
	"github.com/haccer/available"
	"strings"
)

func getSrcLinks(htmlData []byte, baseurl string){
	scriptExp := regexp.MustCompile(`<script[^>]+\bsrc=["']([^"']+)["']`)

	scriptMatchSlice := scriptExp.FindAllStringSubmatch(string(htmlData), -1)

	for _, item := range scriptMatchSlice {
		if strings.Contains(item[1], string("http")) == true{
			fmt.Println("Script SRC found : ", item[1])

			checkDomainAvailable(item[1])
		}else{
			fmt.Println("Script SRC found : ", baseurl+item[1])
			checkDomainAvailable(baseurl+item[1])
		}
	}
}

func checkDomainAvailable(domainname string){
	available := available.Domain(domainname)
	if available {
		fmt.Println("[+] Domain not registed!")
	}else{
		fmt.Println("Domain is registed")
	}
}

func ScanSignature(url string) () {
	return
}