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
func getURLHeaderByKey(url string) string {
	headers := getHeaders(url)

	key := "Content-Type"

	if value, ok := headers[key]; ok {
		return value.(string)
	}

	return ""
}
