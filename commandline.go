package main

import (
	"fmt"
	"main/iamrolepolicyparsing"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Expected 1 cmd line argument, got", len(os.Args))
		fmt.Println("Usage: ./commandline [FILENAME]")
		os.Exit(1)
	}

	json, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Println("Error reading file:", err.Error())
		os.Exit(1)
	}

	iamRolePolicy := iamrolepolicyparsing.IamRolePolicy{}
	err = iamRolePolicy.UnmarshalJSON(json)
	if err != nil {
		fmt.Println("Error parsing file:", err.Error())
		os.Exit(1)
	}

	println(iamRolePolicy.HasAStatementResourceAWildcard())
}
