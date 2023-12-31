package entrypoint

import (
	"bytes"

	"github.com/antchfx/xmlquery"
	"github.com/emirpasic/gods/stacks/arraystack"

	"github.com/bountysecurity/gbounty/internal/request"
)

// XMLParamFinder must implement the Finder interface.
var _ Finder = &XMLParamFinder{}

// XMLParamFinder is used to find entrypoints in the request's XML body.
type XMLParamFinder struct {
	lastParamSeen string
}

// NewXMLParamFinder instantiates a new XMLParamFinder.
func NewXMLParamFinder() *XMLParamFinder {
	return &XMLParamFinder{}
}

func (f *XMLParamFinder) Find(req request.Request) []Entrypoint {
	root, err := xmlquery.Parse(bytes.NewReader(req.Body))
	if err != nil {
		// Open questions:
		// - Should we log errors? (Maybe on verbose)
		return nil
	}

	var entrypoints []Entrypoint

	navigator := xmlquery.CreateXPathNavigator(root)

	stack := arraystack.New()
	stack.Push(navigator.Copy())

	for stack.Size() > 0 {
		pop, ok := stack.Pop()
		if !ok { // Question: Should we log it?
			break
		}

		node, ok := pop.(*xmlquery.NodeNavigator)
		if !ok { // Question: Should we log it?
			break
		}

		navigator.MoveTo(node)

		entrypoints = f.appendEntrypoints(entrypoints, root, node.Current())

		if navigator.MoveToChild() {
			stack.Push(navigator.Copy())

			for navigator.MoveToNext() {
				stack.Push(navigator.Copy())
			}
		}
	}

	return entrypoints
}

func (f *XMLParamFinder) appendEntrypoints(entrypoints []Entrypoint, root, curr *xmlquery.Node) []Entrypoint {
	var fn func(string, string) XMLParam

	//nolint:exhaustive
	switch curr.Type {
	case xmlquery.TextNode:
		fn = func(base string, value string) XMLParam { return newXMLParamValue(base, f.lastParamSeen, value) }
	case xmlquery.ElementNode:
		f.lastParamSeen = curr.Data
		fn = newXMLParamName
	default:
		return entrypoints
	}

	tmp := curr.Data
	curr.Data = xmlReplace
	entrypoints = append(entrypoints, fn(root.OutputXML(false), tmp)) //nolint:wsl
	curr.Data = tmp

	for i := range curr.Attr {
		attrName := curr.Attr[i].Name.Local
		// Attribute name
		tmp = attrName
		curr.Attr[i].Name.Local = xmlReplace
		entrypoints = append(entrypoints, newXMLAttrName(root.OutputXML(false), tmp)) //nolint:wsl
		curr.Attr[i].Name.Local = tmp

		// Attribute V
		tmp = curr.Attr[i].Value
		curr.Attr[i].Value = xmlReplace
		entrypoints = append(entrypoints, newXMLAttrValue(root.OutputXML(false), attrName, tmp)) //nolint:wsl
		curr.Attr[i].Value = tmp
	}

	return entrypoints
}
