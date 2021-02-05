package main

import (
	"fmt"
	"net/http"
)

func getCookies(url string){

	fmt.Println("======Cookie CHECK==========")


	//Vraagt de headers op van een url
	response, err := http.Head(url)
	if err != nil {
		fmt.Println("Not able to Fetch URL")
	}

	//Gaat door alle cookies heen en plaatst deze in een map
	for _, cookie := range response.Cookies() {

		if cookie.Secure == false{
			fmt.Println("[+] Found a cookie without secure flag named:", cookie.Name)
		}

		if cookie.HttpOnly == false{
			fmt.Println("[+] Found a cookie without httponly flag named:", cookie.Name)

		}
	}

	fmt.Println("======END Cookie CHECK==========\n")

}