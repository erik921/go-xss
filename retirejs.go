package main

import (
	"fmt"
	"regexp"
)

func ScanSignature(url string) () {
	return
}

func getSrcLinks(htmlData []byte){
	scriptExp := regexp.MustCompile(`<script[^>]+`)
	scriptMatchSlice := scriptExp.FindAllStringSubmatch(string(htmlData), -1)

	for _, item := range scriptMatchSlice {
		fmt.Println("Script SRC found : ", item)
	}
}