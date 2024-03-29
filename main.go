package main

import (
	"bufio"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/steelx/extractlinks"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

//Making my own Client so I can ignore SSL certificates
var config = &tls.Config{InsecureSkipVerify: true}
var transport = &http.Transport{TLSClientConfig: config}
var customWebclient = &http.Client{Transport: transport}

var urlCrawlQueue = make(chan string)
var crawlerVisited = make(map[string]bool)

var getParameterScanned = make(map[string]bool)
var bruteforceGetParametersQueue = make(chan string)

var xssScannerQueue = make(chan string)
var xsshits = make(map[string]bool)

var verboseBool *bool
var showUrls *bool
var showSrc *bool
var showReflectedGetParameters *bool
var showPotentialGetParameters *bool


var mu sync.Mutex
//var hash string

var foundParameters []string



func main() {
	targetUrl := flag.String("url", "", "Target URL. (Required)")
	RecursiveBool := flag.Bool("recursion", false, "Scan urls recursively.")
	verboseBool = flag.Bool("verbose", false, "Scan urls recursively.")
	showUrls = flag.Bool("showurls", false, "Shows all the found urls.")
	showSrc = flag.Bool("showsrc", false, "Shows all the found SRC links.")
	showReflectedGetParameters = flag.Bool("showreflected", false, "Show the Reflected GET Parameters.")
	showPotentialGetParameters = flag.Bool("showpotential", false, "Show the Potential GET Parameters.")






	flag.Parse()

	//generate random hash
	rand.Seed(time.Now().UnixNano())

	//Check if the URL is provided
	if *targetUrl == "" {
		fmt.Println("It's required to have the URL!")
		fmt.Println("For more information see the man page below")
		flag.PrintDefaults()
		os.Exit(1)
	}


	//Program continues with this if url is set
	baseurl := *targetUrl
	fmt.Println("====Starting go-xss on domain:", baseurl, "=====\n")

	//Get headers and analyse them
	getURLHeaderByKey(baseurl)

	//Get Cookies and analyse them
	getCookies(baseurl)

	//Check if /GIT/ is available on server
	sensitiveFileChecker(baseurl)

	//Add Base URL to queue
	go func () {
		urlCrawlQueue <- baseurl

	}()

	go func(){
		if *RecursiveBool == true {
			fmt.Println("Searching recursively")

			//Keep Crawling URLS
			go func(){
				for href := range urlCrawlQueue{
					if !crawlerVisited[href] && sameDomainCheck(href, baseurl)  {
						crawlUrlLinks(href)
					}
				}
			}()

		}else{
			href := <-urlCrawlQueue
			crawlUrlLinks(href)
		}
	}()

	go func(){
		for bruteforceHref := range bruteforceGetParametersQueue{
			guessParameterBruteforce(bruteforceHref)
		}
	}()

	for xssHref := range xssScannerQueue{
		xssScanner(xssHref)
	}

}


////////////////////////////////////////////
///// THIS BLOCK IS WHERE FUNCTIONS START///
////////////////////////////////////////////

func xssAnalysis(xsshref string){
	hash := "goxss-" + strconv.Itoa(rand.Int())

	response, err := customWebclient.Get(xsshref+hash)
	checkErr(err)
	defer response.Body.Close()

	scanner := bufio.NewScanner(response.Body)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), hash) == true {

			//Check if payload is being placed inside of a link tag
			if strings.Contains(scanner.Text(), "a href=") == true{
				if *showReflectedGetParameters == true {
					fmt.Println("Payload displayed inside of link tag!", xsshref+hash)
				}
			}

			//Check if payload is being placed after = inside of html
			if strings.Contains(scanner.Text(), "=goxss") == true{
				if *showReflectedGetParameters == true {
					fmt.Println("Payload being placed inside of attribute!", xsshref+hash)
				}
			}

			if *showReflectedGetParameters == true{
				fmt.Println("=====================================================================")
				fmt.Println("Keyword reflected", xsshref)
				fmt.Println(scanner.Text())
				fmt.Println("=====================================================================")
			}

		}
	}

}

func xssScanner(xsshref string){

	//If verbose is set show starting xss on which domain
	logPrint("Starting XSS Scan on ", xsshref)

	xssPayloadFile, err := os.Open(`C:\Users\Erik\Desktop\Go Projects\udemy-learn-go\goxss\xsspayloads.txt`)
	checkErr(err)
	defer xssPayloadFile.Close()


	//Analyis of parameter
	xssAnalysis(xsshref)

	//Start bruteforcing payloads as last resort
	scanner := bufio.NewScanner(xssPayloadFile)
	for scanner.Scan() {
		if !xsshits[xsshref]{
			xsspayload := scanner.Text()
			if checkBodyFor(xsspayload,xsshref+xsspayload) == true{
				fmt.Println("++++ [XSS FOUND with payload bruteforcer] ++++ ", xsshref+xsspayload)
				xsshits[xsshref] = true
			}
		}else{
			logPrint("Skipping Url already exploited: ", xsshref)
			}

	}

}

//Bruteforcing for get parameters
func guessParameterBruteforce(bruteforceHref string){

	//If verbose is set it will output which domain is getting bruteforced for GET parameter
	logPrint("Starting GET Parameter Bruteforce for: ", bruteforceHref)

	//Marking URL as scanned
	getParameterScanned[bruteforceHref] = true

	//Getting the parameter file
	getParameterFile, err := os.Open(`C:\Users\Erik\Desktop\Go Projects\udemy-learn-go\goxss\getparameters.txt`)
	checkErr(err)
	defer getParameterFile.Close()

	//Generate Hash
	hash := "goxss-" + strconv.Itoa(rand.Int())

	//Scan found parameters
	for _, parameter := range foundParameters {
		domainOnlyRegex := regexp.MustCompile("\\?.*$")
		domainOnly := domainOnlyRegex.ReplaceAllString(bruteforceHref, "")
		logPrint("Testing included variable", domainOnly+"?"+parameter+"=")
		domainWithParameter := domainOnly+"?"+parameter+"="

		if checkBodyFor(hash,domainWithParameter+hash) == true{

			if *showPotentialGetParameters == true{
				fmt.Println("[+] Potenial Get Parameter found! ", domainWithParameter)

			}

			go func () {
				xssScannerQueue <- domainWithParameter
			}()
		}

	}

	//Scan with Bruteforce
	scanner := bufio.NewScanner(getParameterFile)
	for scanner.Scan() {
		mu.Lock()
		getParameterurl := ""

		if strings.Contains(bruteforceHref, "?") == true {
			getParameterurl = bruteforceHref+"&"+scanner.Text()+"="

			}else {
			getParameterurl = bruteforceHref+"?"+scanner.Text()+"="

		}

		//if verbose is set show which get parameter is getting checked
		logPrint("Checking Get Parameter", getParameterurl+hash)


		if checkBodyFor(hash,getParameterurl+hash) == true{

			if *showPotentialGetParameters == true{
				fmt.Println("[+] Potenial Get Parameter found! ", getParameterurl)

			}

			go func () {
				xssScannerQueue <- getParameterurl
			}()
		}
		mu.Unlock()
	}
}


func checkBodyFor(keyword string, url string) bool {
	response, err := customWebclient.Get(url)
	checkErr(err)

	defer response.Body.Close()
	scanner := bufio.NewScanner(response.Body)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), keyword) == true {
			logPrint("Keyword reflected: ",scanner.Text())
			return true
		}
	}
	return false
}


//Check if the URL is also in Scope
func sameDomainCheck(href, baseURL string) bool{
	uri, err := url.Parse(href)
	if err != nil{
		return false
	}
	parentUri, err := url.Parse(baseURL)
	if err != nil{
		return false
	}

	if uri.Host != parentUri.Host {
		logPrint("Skipping, not same domain: ", uri.Host)
		return false
	}

	return true
}

//Creates a full URL that can be processed
func createFullUrl(href, baseURL string) string{
	uri, err := url.Parse(href)
	if err != nil{
		return ""
	}
	base, err := url.Parse(baseURL)
	if err != nil{
		return ""
	}
	fixedUri := base.ResolveReference(uri)

	return fixedUri.String()
}

//Will crawl the URL for links
func crawlUrlLinks(href string){

	//Add url to visited map
	crawlerVisited[href] = true

	if *showUrls == true{
		fmt.Println("Found URL: ",href)
	}

	//? means the url has parameters so they need to be processed and checked
	if strings.Contains(href,"?"){
		foundParameters = paramFinder(href, foundParameters)
	}


	go func () {
		bruteforceGetParametersQueue <- href
	}()


	//Check if the link might be going to unregisted domain, Potential Phishing!
	if checkDomainAvailable(href) == true{
		fmt.Println("[+] Domain not registered!: ", href)
	}

	//Makes a webrequest to the TargetURL
	logPrint("Started Crawling: ", href)
	response, err := customWebclient.Get(href)
	checkErr(err)
	defer response.Body.Close()

	resp, err := http.Get(href)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	htmlData, _ := ioutil.ReadAll(resp.Body)

	//scans SRC for outdated Jquery and if domain is still registered
	getSrcLinks(htmlData,href)

	//Checks all links if domain is still registered
	checkLinkUrl(htmlData,href)

	//Will get the links from the Body of the webrequest
	links, _ := extractlinks.All(response.Body)


	for _, link := range links{
		wholeUrl := createFullUrl(link.Href, href)
		go func (url string) {
			urlCrawlQueue <- wholeUrl
		}(wholeUrl)
	}
}

//This function allows to get the parameters from the request
func paramFinder(domain string, foundParameters []string) []string{
	paramstart := strings.Split(domain, "?")[1]
	params := strings.Split(paramstart, "&")
	for _, param := range params {

		percentSpl := strings.Split(param, "%")

		//Checking if value needs decoding
		var strPara string
		if len(percentSpl) > 1 {
			for i, j := range percentSpl {
				if i == 0 {
					strPara += j
				} else {
					bl, _ := hex.DecodeString(j[:2])
					strung := string(bl)
					strPara += strung
					strPara += j[2:]
					foundParameters = append(foundParameters, strPara)

				}
			}
		} else {

			//Regex to replace values from parameters
			removeValueRegex := regexp.MustCompile("=.*$")
			strPara := removeValueRegex.ReplaceAllString(param, "")
			foundParameters = append(foundParameters, strPara)

		}

		foundParameters = append(foundParameters)

	}
	return foundParameters
}

func sensitiveFileChecker(url string){

	fmt.Println("======GIT CHECK==========")

	gitLink := url+"/.git/HEAD"

	logPrint("Checking if git is exposed", gitLink)

	response, err := customWebclient.Get(gitLink)
	checkErr(err)
	defer response.Body.Close()

	if response.StatusCode >= 200 && response.StatusCode <= 299{
		fmt.Println("[++] GIT directory might be exposed!", gitLink)


	}
	logPrint("Git directory not exposed for: ", gitLink)
	fmt.Println("GIT Directory Server responded with was: ", http.StatusText(response.StatusCode))

	fmt.Println("======END GIT CHECK==========\n")

}


/////////////////////////////////////
////// Error and Log processing//////
//////////////////////////////////////

//Function to catch the errors and process them.
//Will also exit program in case of error
func checkErr(err error){
	if err != nil {
		fmt.Println("==Error==")
		fmt.Println(err)
		os.Exit(1)
	}
}

func logPrint(output, argument string){
	if *verboseBool == true{
		fmt.Println(output, argument)
	}
}