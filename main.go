package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/steelx/extractlinks"
	"net/http"
	"net/url"
	"os"
	"strings"
)

//Making my own Client so I can ignore SSL certificates
var config = &tls.Config{InsecureSkipVerify: true,}
var transport = &http.Transport{TLSClientConfig: config}
var customWebclient = &http.Client{Transport: transport}
var urlCrawlQueue = make(chan string)
var crawlerVisited = make(map[string]bool)
var getParameterScanned = make(map[string]bool)
var bruteforceGetParametersQueue = make(chan string)

func main() {
	targetUrl := flag.String("url", "", "Target URL. (Required)")
	RecursiveBool := flag.Bool("recursion", false, "Scan urls recursively.")
	flag.Parse()

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

	if *RecursiveBool == true {
		fmt.Println("Searching recursively")

		//Queue for Crawling
		go func () {
			urlCrawlQueue <- baseurl

		}()

		//Keep Crawling URLS
		go func(){
			for href := range urlCrawlQueue{
				if !crawlerVisited[href] && sameDomainCheck(href, baseurl)  {
					crawlUrlLinks(href)
				}
			}
		}()

		//Queue for Bruteforce get parameters
		go func () {
			bruteforceGetParametersQueue <- baseurl

		}()

		//Keep Crawling URLS
		for bruteforceHref := range bruteforceGetParametersQueue{
			guessParameterBruteforce(bruteforceHref)
		}
	}
}


////////////////////////////////////////////
///// THIS BLOCK IS WHERE FUNCTIONS START///
////////////////////////////////////////////

//Bruteforcing for get parameters
func guessParameterBruteforce(bruteforceHref string){

	getParameterScanned[bruteforceHref] = true

	fmt.Println("Starting GET Parameter Bruteforce for: ", bruteforceHref)
	checkBodyFor("test",bruteforceHref)
}


func checkBodyFor(keyword string, url string) {
	response, err := customWebclient.Get(url)
	defer response.Body.Close()
	checkErr(err)

	scanner := bufio.NewScanner(response.Body)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), string(keyword)) == true {
			fmt.Println(scanner.Text())
		}
	}
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

	//Makes a webrequest to the TargetURL
	fmt.Println("Started Crawling: ", href)
	response, err := customWebclient.Get(href)
	defer response.Body.Close()
	checkErr(err)

	//Will get the Body of the previous webrequest
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
		fmt.Println(err)
		os.Exit(1)
	}
}