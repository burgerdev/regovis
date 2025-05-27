# regovis

`regovis` is a tool for visualizing complex [Rego] modules.
It parses a given Rego file and builds a hierarchy of rules.
The rules can then be queried, like an OPA agent, and a tree of all rules relevant for this query is returned.

[Rego]: https://www.openpolicyagent.org/docs/policy-language

## Usage

```raw
regovis [-dot|-json] [-depth INT] [-query FUNCTION_NAME/ARITY] FILE
```

## Example

This program identifies rules with their name, arity (number of arguments) and index in the file.
For example, the [`samples/simple.rego`] contains [two] [rules] `CreateContainerRequest` with no arguments.
The first of these is just a default rule that does not call other rules, but the second one calls `allow_anno/2`, which in turn has two implementations.
The resulting call tree for the zero argument `CreateContainerRequest`, cut off at depth 2, should look something like this:

```console
$ go run ./ -query CreateContainerRequest/0 -depth 2 samples/simple.rego 
CreateContainerRequest/0[0]
CreateContainerRequest/0[1]
  allow_anno/2[0]
  allow_anno/2[1]
```

[two]: https://github.com/burgerdev/regovis/blob/8899ba10671b91dc0ed12abe9820c0b9e20078a6/samples/simple.rego#L12
[rules]: https://github.com/burgerdev/regovis/blob/8899ba10671b91dc0ed12abe9820c0b9e20078a6/samples/simple.rego#L14

## Output

The default output format is a tree of functions, where increased indentation marks a parent-child relationship.
Alternatively, the tool can generate a [dot] graph with the `-dot` flag.
The `-json` flag dumps the internal call tree representation as JSON.

[dot]: https://graphviz.org/doc/info/lang.html

## Scope

The main goal of this tools is to help analyzing [Rego policies for Kata Containers].
I don't have plans to add language features beyond this, and I don't aim to make this a general purpose tool.

[Rego policies for Kata Containers]: https://github.com/kata-containers/kata-containers/blob/main/src/tools/genpolicy/genpolicy-auto-generated-policy-details.md
