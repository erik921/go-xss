package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/steelx/extractlinks"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
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



var mu sync.Mutex
var hash string

func main() {
	targetUrl := flag.String("url", "", "Target URL. (Required)")
	RecursiveBool := flag.Bool("recursion", false, "Scan urls recursively.")
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
	fmt.Println("Starting go-xss on domain:", baseurl)

	//Get headers and analyse them
	getURLHeaderByKey(baseurl)

	//Get Cookies and analyse them
	getCookies(baseurl)

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

func xssScanner(xsshref string){
	//fmt.Println("Starting XSS Scan on ", xsshref)
	xssPayloadFile, err := os.Open(`C:\Users\Erik\Desktop\Go Projects\udemy-learn-go\goxss\xsspayloads.txt`)
	checkErr(err)
	defer xssPayloadFile.Close()

	scanner := bufio.NewScanner(xssPayloadFile)
	for scanner.Scan() {
		if !xsshits[xsshref]{
			xsspayload := scanner.Text()
			if checkBodyFor(xsspayload,xsshref+xsspayload) == true{
				fmt.Println("++++ [XSS FOUND] ++++ ", xsshref+xsspayload)
				xsshits[xsshref] = true
			}
		}else{
			fmt.Println("Skipping Url already exploited: ", xsshref)
		}

	}

}

//Bruteforcing for get parameters
func guessParameterBruteforce(bruteforceHref string){

	//fmt.Println("Starting GET Parameter Bruteforce for: ", bruteforceHref)
	//Marking URL as scanned
	getParameterScanned[bruteforceHref] = true

	//Getting the parameter file
	getParameterFile, err := os.Open(`C:\Users\Erik\Desktop\Go Projects\udemy-learn-go\goxss\getparameters.txt`)
	checkErr(err)
	defer getParameterFile.Close()

	//Generate Hash
	hash := "goxss-" + strconv.Itoa(rand.Int())

	scanner := bufio.NewScanner(getParameterFile)
	for scanner.Scan() {
		mu.Lock()
		getParameterurl := ""

		if strings.Contains(bruteforceHref, string("?")) == true {
			getParameterurl = bruteforceHref+"&"+scanner.Text()+"="

			}else {
			getParameterurl = bruteforceHref+"?"+scanner.Text()+"="

		}
		//fmt.Println("Checking Get Parameter", getParameterurl+hash)

		if checkBodyFor(hash,getParameterurl+hash) == true{
			go func () {
				fmt.Println("++ Potenial Get Parameter found! ", getParameterurl)
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
		if strings.Contains(scanner.Text(), string(keyword)) == true {
			fmt.Println("Keyword reflected: ",scanner.Text())
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
		fmt.Printf("Skipping, %v not same domain\n", uri.Host)
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

	go func () {
		bruteforceGetParametersQueue <- href
	}()


	//Check if the link might be going to unregisted domain, Potential Phising!
	if checkDomainAvailable(href) == true{
		fmt.Println("[+] Domain not registed!: ", href)
	}

	//Makes a webrequest to the TargetURL
	//fmt.Println("Started Crawling: ", href)
	response, err := customWebclient.Get(href)
	checkErr(err)
	defer response.Body.Close()

	resp, err := http.Get(href)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	htmlData, _ := ioutil.ReadAll(resp.Body)

	getSrcLinks(htmlData,href)

	//Will get the links from the Body of the webrequest
	links, _ := extractlinks.All(response.Body)


	for _, link := range links{
		wholeUrl := createFullUrl(link.Href, href)
		go func (url string) {
			urlCrawlQueue <- wholeUrl
		}(wholeUrl)
	}
}

//Function to catch the errors and process them.
//Will also exit program in case of error
func checkErr(err error){
	if err != nil {
		fmt.Println("==Error==")
		fmt.Println(err)
		os.Exit(1)
	}
}