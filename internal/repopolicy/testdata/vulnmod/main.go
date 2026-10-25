// Command vulnmod calls language.Parse from golang.org/x/text v0.3.5, a symbol
// govulncheck reports as reachable under GO-2021-0113.
package main

import (
	"fmt"

	"golang.org/x/text/language"
)

func main() {
	tag, err := language.Parse("en-US")
	fmt.Println(tag, err)
}
