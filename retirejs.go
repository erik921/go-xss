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
			ScanSignature(item[1])

			checkDomainAvailable(item[1])
		}else{
			fmt.Println("Script SRC found : ", baseurl+item[1])
			if checkDomainAvailable(baseurl+item[1]) == true{
				fmt.Println("[+] SRC Domain not registed!", baseurl+item[1])
			}
			ScanSignature(baseurl+item[1])
		}
	}
}

func checkDomainAvailable(domainname string)bool{
	available := available.Domain(domainname)
	if available {
		fmt.Println("[+] Domain not registed!")
		return true
	}
	return false
}

func ScanSignature(url string) () {

	jqueryRegexCheck, _ := regexp.MatchString(`jquery-[0-3].[0-5]`,url)
	jqueryRegexCheck2, _ := regexp.MatchString(`jquery-3.5.1`,url)


	if jqueryRegexCheck == true && jqueryRegexCheck2 == false{
		fmt.Println("[++] Jquery is outdated!: ", url)
	}

	return
}