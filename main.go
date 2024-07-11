package main

import (
	"encoding/json"
    "flag"
    "fmt"
	"log"
	"os"

	"github.com/open-policy-agent/opa/ast"
)

func main() {
    flag.Parse()
    file := flag.Arg(0)
    if file == "" {
        log.Fatal("Usage: regovis FILE")
    }

	policy, err := os.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}
	module, err := ast.ParseModule("policy.rego", string(policy))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Package: %q\n", module.Package)

	for _, rule := range module.Rules {
		s, err := json.MarshalIndent(rule.Head, "  ", "  ")
		if err != nil {
			log.Fatal(err)
		}
        fmt.Printf("  %s\n", s)

        if rule.Head.Name != "allow_anno" {
            continue
        }

		s, err = json.MarshalIndent(rule.Body, "  ", "  ")
		if err != nil {
			log.Fatal(err)
		}
        fmt.Printf("  %s\n", s)
	}
}
