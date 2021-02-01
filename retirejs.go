package main

import (
	"fmt"
	"regexp"
)

func getSrcLinks(htmlData []byte){
	scriptExp := regexp.MustCompile(`<script[^>]+\bsrc=["']([^"']+)["']`)

	scriptMatchSlice := scriptExp.FindAllStringSubmatch(string(htmlData), -1)

	for _, item := range scriptMatchSlice {
		fmt.Println("Script SRC found : ", item[1])
	}
}

func ScanSignature(url string) () {
	return
}