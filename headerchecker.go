package main

import (
	"fmt"
	"net/http"
	"strings"
)

func getHeaders(url string) map[string]interface {}{

	//Vraagt de headers op van een url
	response, err := http.Head(url)
	if err != nil {
		fmt.Println("Not able to Fetch URL")
	}

	headers := make(map[string]interface{})

	//Gaat door alle headers heen en plaatst deze in een map
	for k, v := range response.Header {
		headers[strings.ToLower(k)] = string(v[0])
	}

	//Geef de map terug
	return headers
}

//fuction to check header with a string
//Returns the string of the header.
//If the header is not in the map it will return an empty string.
func getURLHeaderByKey(url string){
	headers := getHeaders(url)

	xssheader := "X-XSS-Protection"
	xframeheader := "X-Frame-Options"
	contentheader := "X-Content-Type-Options"
	cspheader := "Content-Security-Policy"

	fmt.Println("======HEADER CHECK==========")

	//Checks the xssheader
	if value, ok := headers[xssheader]; ok {
		fmt.Println(value.(string))
		}else{
		fmt.Println("XSS Protection header not found!")
	}

	//Checks the xframe header
	if value, ok := headers[xframeheader]; ok {
		fmt.Println(value.(string))
	}else{
		fmt.Println("Iframe protection header not found!")


	}

	//checks the content type header
	if value, ok := headers[contentheader]; ok {
		fmt.Println(value.(string))
	}else{
		fmt.Println("Content Type header not found!")
	}

	//checks the csp header
	if value, ok := headers[cspheader]; ok {
		fmt.Println(value.(string))
	}else{
		fmt.Println("CSP Policy header not found!")

	}

	fmt.Println("======= END HEADER CHECK======")

}
