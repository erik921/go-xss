package main

import (
	"bufio"
	"fmt"
	"github.com/haccer/available"
	"regexp"
	"strings"
)

var getScriptFound = make(map[string]bool)
var getLinkFound = make(map[string]bool)



func getSrcLinks(htmlData []byte, baseurl string){
	scriptExp := regexp.MustCompile(`<script[^>]+\bsrc=["']([^"']+)["']`)

	scriptMatchSlice := scriptExp.FindAllStringSubmatch(string(htmlData), -1)

	for _, item := range scriptMatchSlice {
		if !getScriptFound[item[1]]{
			if strings.Contains(item[1], string("http")) == true{

				if strings.Contains(baseurl,item[1]){
					fmt.Println("[+] Javascript is being loaded from external domain")
					checkDomainAvailable(item[1])

				}

				fmt.Println("Script SRC found : ", item[1])
				ScanSignature(item[1])

				//Add script to list of found src
				getScriptFound[item[1]] = true

				//Scanning src for secrets
				secretScan(item[1])

			}else{
				logPrint("Script SRC found : ", baseurl+item[1])
				//Add script to list of found src
				getScriptFound[baseurl+item[1]] = true

				//Scanning SRC for secrets
				secretScan(baseurl+item[1])

				if checkDomainAvailable(baseurl+item[1]) == true{
					fmt.Println("[+] SRC Domain not registed!", baseurl+item[1])

				}
				ScanSignature(baseurl+item[1])
			}
		}else{
			logPrint("SRC script already found", "")
		}
	}
}

func checkLinkUrl(htmlData []byte, baseurl string){
	hrefregex := regexp.MustCompile(`<a[^>]+\bhref=["']([^"']+)["']`)

	scriptMatchSlice := hrefregex.FindAllStringSubmatch(string(htmlData), -1)

	for _, item := range scriptMatchSlice {
		if !getLinkFound[item[1]]{
			if strings.Contains(item[1], string("http")) == true{
				logPrint("HREF link found: ", item[1])
				checkDomainAvailable(item[1])

				//Add script to list of found src
				getLinkFound[item[1]] = true

			}else{
				logPrint("HREF link found: ", baseurl+item[1])
				//Add script to list of found src
				getLinkFound[baseurl+item[1]] = true

				if checkDomainAvailable(baseurl+item[1]) == true{
					fmt.Println("[+] HREF Domain not registed!", baseurl+item[1])

				}
			}
		}else{
			logPrint("Href was already found", "")
		}
	}
}

//Function that checks JS files for secrets
func secretScan(srcUrl string){
	fmt.Println("Scanning SRC for secrets", srcUrl)

	response, err := customWebclient.Get(srcUrl)
	checkErr(err)
	defer response.Body.Close()

	scanner := bufio.NewScanner(response.Body)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "secret=",) || strings.Contains(scanner.Text(), "secret:") == true {
			fmt.Println("[+] Possible secret found: ",scanner.Text())

		}

		if strings.Contains(scanner.Text(), "api-key=",) || strings.Contains(scanner.Text(), "api-key:") == true {
			fmt.Println("Possible API-key: ",scanner.Text())

		}

		if strings.Contains(scanner.Text(), "password=",) || strings.Contains(scanner.Text(), "password:") == true {
			fmt.Println("Possible password found: ",scanner.Text())

		}
	}

}


//Function to check if a domain is available for registration
func checkDomainAvailable(domainname string)bool{
	available := available.Domain(domainname)
	if available {
		//domain is nog registered returns true
		return true
	}
	//domain registered returns false
	logPrint("Checked domain but its registed", domainname)
	return false
}

//Function that will check if the version of Jquery is outdated
func ScanSignature(url string) () {

	jqueryRegexCheck, _ := regexp.MatchString(`jquery-[0-3].[0-5]`,url)
	jqueryRegexCheck2, _ := regexp.MatchString(`jquery-3.5.1`,url)


	if jqueryRegexCheck == true && jqueryRegexCheck2 == false{
		fmt.Println("[++] Jquery is outdated!: ", url)
	}

	return
}