package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/emicklei/dot"
	"github.com/open-policy-agent/opa/ast"
)

func main() {
	query := RuleKey{
		Name:  "CreateContainerRequest",
		Arity: 0,
	}
	flag.Func("query", "predicate to look up (default: CreateContainerRequest)", func(s string) error {
		name, arityStr, ok := strings.Cut(s, "/")
		if !ok {
			return fmt.Errorf("format for query: NAME/ARITY")
		}
		arity, err := strconv.Atoi(arityStr)
		if err != nil {
			return fmt.Errorf("parsing arity: %w", err)
		}
		query.Name = name
		query.Arity = arity
		return nil
	})
	var depth = flag.Int("depth", -1, "maximum depth of call stack (less than 0 means infinity)")
	var jsonOutput = flag.Bool("json", false, "JSON output")
	var graphvizOutput = flag.Bool("dot", false, "Graphviz output")
	var help = flag.Bool("h", false, "show help")
	flag.BoolVar(help, "help", false, "show help")

	flag.Parse()
	file := flag.Arg(0)
	if file == "" || *help {
		log.Fatal("Usage: regovis [-dot|-json] [-depth INT] [-query FUNCTION_NAME] FILE")
	}

	policy, err := os.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}
	module, err := ast.ParseModule("policy.rego", string(policy))
	if err != nil {
		log.Fatal(err)
	}

	ruleStore := make(RuleStore)

	for _, rule := range module.Rules {
		key := RuleKey{Name: rule.Head.Name.String(), Arity: len(rule.Head.Args)}
		ruleStore[key] = append(ruleStore[key], rule)
	}

	ts := BuildCallTree(ruleStore, query, *depth)

	switch {
	case *jsonOutput:
		pretty, err := json.MarshalIndent(ts, "", "  ")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(pretty))
	case *graphvizOutput:
		g := dot.NewGraph(dot.Directed)
		for _, t := range ts {
			t.Walk(func(t *CallTree) {
				n := g.Node(t.String())

				for _, subt := range t.Calls {
					c := g.Node(subt.String())
					if len(g.FindEdges(n, c)) == 0 {
						g.Edge(n, c)
					}
				}
			})
		}
		fmt.Println(g.String())
	default:
		for _, t := range ts {
			t.Render("")
		}
	}

}

// RuleKey is the unique identifier for a rule (I hope).
type RuleKey struct {
	Name  string
	Arity int
}

func (k RuleKey) String() string {
	return fmt.Sprintf("%s/%d", k.Name, k.Arity)
}

type RuleStore map[RuleKey][]*ast.Rule

// CallTree is a pseudo-AST that only contains top-level rules.
type CallTree struct {
	Key   RuleKey
	Index int
	Calls []*CallTree
}

func (t *CallTree) String() string {
	return fmt.Sprintf("%s[%d]", t.Key, t.Index)
}

func (t *CallTree) MarshalJSON() ([]byte, error) {
	m := map[string]any{
		"key":   t.Key.String(),
		"index": t.Index,
		"calls": t.Calls,
	}
	return json.Marshal(m)
}

func BuildCallTree(store RuleStore, key RuleKey, depth int) []*CallTree {
	if depth == 0 {
		return nil
	}
	rules, ok := store[key]
	if !ok {
		return nil
	}
	var out []*CallTree
	for i, rule := range rules {
		t := &CallTree{
			Key:   key,
			Index: i,
		}
		for _, k := range getNestedRules(rule.Body) {
			subt := BuildCallTree(store, k, depth-1)
			t.Calls = append(t.Calls, subt...)
		}
		out = append(out, t)
	}
	return out
}

// Render pretty-prints the tree to stdout.
func (t *CallTree) Render(prefix string) {
	fmt.Printf("%s%s\n", prefix, t)
	for _, subt := range t.Calls {
		if slices.Contains([]string{"print"}, subt.Key.Name) {
			continue
		}
		subt.Render(prefix + "  ")
	}
}

func (t *CallTree) Walk(f func(*CallTree)) {
	f(t)
	for _, subt := range t.Calls {
		subt.Walk(f)
	}
}

// getNestedRules returns all rules called directly from somewhere in the body.
func getNestedRules(body ast.Body) []RuleKey {
	var out []RuleKey
	for _, expr := range body {
		if expr.IsEvery() {
			return getNestedRules(expr.Terms.(*ast.Every).Body)
		}
		if !expr.IsCall() || expr.IsAssignment() || expr.IsEquality() {
			continue
		}

		terms := expr.Terms.([]*ast.Term)
		ref := terms[0].Value.(ast.Ref)
		k := RuleKey{
			Name:  ref[0].Value.String(),
			Arity: len(terms) - 1,
		}
		out = append(out, k)
	}
	return out
}
