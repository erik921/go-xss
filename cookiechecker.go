package main

import (
	"fmt"
	"net/http"
)

func getCookies(url string){

	//Vraagt de headers op van een url
	response, err := http.Head(url)
	if err != nil {
		fmt.Println("Not able to Fetch URL")
	}

	//Gaat door alle cookies heen en plaatst deze in een map
	for _, cookie := range response.Cookies() {
		fmt.Println("Found a cookie named:", cookie.Name)
	}
}