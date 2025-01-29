package entrypoint_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/BountySecurity/gbounty/entrypoint"
	"github.com/BountySecurity/gbounty/profile"
	"github.com/BountySecurity/gbounty/request"
)

func TestXMLParamFinder_Find_Replace(t *testing.T) {
	t.Parallel()

	const payload = "/.git/HEAD"

	req := request.Request{Body: []byte(`<person sex="female"><firstname>Anna</firstname><lastname><first>Smith</first><second>Smith</second></lastname></person>`)}
	exp := [][]byte{
		[]byte(`<?xml version="1.0"?></.git/HEAD sex="female"><firstname>Anna</firstname><lastname><first>Smith</first><second>Smith</second></lastname><//.git/HEAD>`),
		[]byte(`<?xml version="1.0"?><person /.git/HEAD="female"><firstname>Anna</firstname><lastname><first>Smith</first><second>Smith</second></lastname></person>`),
		[]byte(`<?xml version="1.0"?><person sex="/.git/HEAD"><firstname>Anna</firstname><lastname><first>Smith</first><second>Smith</second></lastname></person>`),
		[]byte(`<?xml version="1.0"?><person sex="female"><firstname>Anna</firstname></.git/HEAD><first>Smith</first><second>Smith</second><//.git/HEAD></person>`),
		[]byte(`<?xml version="1.0"?><person sex="female"><firstname>Anna</firstname><lastname><first>Smith</first></.git/HEAD>Smith<//.git/HEAD></lastname></person>`),
		[]byte(`<?xml version="1.0"?><person sex="female"><firstname>Anna</firstname><lastname><first>Smith</first><second>/.git/HEAD</second></lastname></person>`),
		[]byte(`<?xml version="1.0"?><person sex="female"><firstname>Anna</firstname><lastname></.git/HEAD>Smith<//.git/HEAD><second>Smith</second></lastname></person>`),
		[]byte(`<?xml version="1.0"?><person sex="female"><firstname>Anna</firstname><lastname><first>/.git/HEAD</first><second>Smith</second></lastname></person>`),
		[]byte(`<?xml version="1.0"?><person sex="female"></.git/HEAD>Anna<//.git/HEAD><lastname><first>Smith</first><second>Smith</second></lastname></person>`),
		[]byte(`<?xml version="1.0"?><person sex="female"><firstname>/.git/HEAD</firstname><lastname><first>Smith</first><second>Smith</second></lastname></person>`),
	}

	finder := entrypoint.NewXMLParamFinder()
	entrypoints := finder.Find(req)
	builtBodies := make([][]byte, 0, len(entrypoints))

	for _, e := range entrypoints {
		injReq := e.InjectPayload(req, profile.Replace, payload)
		builtBodies = append(builtBodies, injReq.Body)
	}

	assert.ElementsMatch(t, exp, builtBodies)
}

func TestXMLParamFinder_Find_Append(t *testing.T) {
	t.Parallel()

	const payload = "/.git/HEAD"

	req := request.Request{Body: []byte(`<person sex="female"><firstname>Anna</firstname><lastname><first>Smith</first><second>Smith</second></lastname></person>`)}
	exp := [][]byte{
		[]byte(`<?xml version="1.0"?><person/.git/HEAD sex="female"><firstname>Anna</firstname><lastname><first>Smith</first><second>Smith</second></lastname></person/.git/HEAD>`),
		[]byte(`<?xml version="1.0"?><person sex/.git/HEAD="female"><firstname>Anna</firstname><lastname><first>Smith</first><second>Smith</second></lastname></person>`),
		[]byte(`<?xml version="1.0"?><person sex="female/.git/HEAD"><firstname>Anna</firstname><lastname><first>Smith</first><second>Smith</second></lastname></person>`),
		[]byte(`<?xml version="1.0"?><person sex="female"><firstname>Anna</firstname><lastname/.git/HEAD><first>Smith</first><second>Smith</second></lastname/.git/HEAD></person>`),
		[]byte(`<?xml version="1.0"?><person sex="female"><firstname>Anna</firstname><lastname><first>Smith</first><second/.git/HEAD>Smith</second/.git/HEAD></lastname></person>`),
		[]byte(`<?xml version="1.0"?><person sex="female"><firstname>Anna</firstname><lastname><first>Smith</first><second>Smith/.git/HEAD</second></lastname></person>`),
		[]byte(`<?xml version="1.0"?><person sex="female"><firstname>Anna</firstname><lastname><first/.git/HEAD>Smith</first/.git/HEAD><second>Smith</second></lastname></person>`),
		[]byte(`<?xml version="1.0"?><person sex="female"><firstname>Anna</firstname><lastname><first>Smith/.git/HEAD</first><second>Smith</second></lastname></person>`),
		[]byte(`<?xml version="1.0"?><person sex="female"><firstname/.git/HEAD>Anna</firstname/.git/HEAD><lastname><first>Smith</first><second>Smith</second></lastname></person>`),
		[]byte(`<?xml version="1.0"?><person sex="female"><firstname>Anna/.git/HEAD</firstname><lastname><first>Smith</first><second>Smith</second></lastname></person>`),
	}

	finder := entrypoint.NewXMLParamFinder()
	entrypoints := finder.Find(req)
	builtBodies := make([][]byte, 0, len(entrypoints))

	for _, e := range entrypoints {
		injReq := e.InjectPayload(req, profile.Append, payload)
		builtBodies = append(builtBodies, injReq.Body)
	}

	assert.ElementsMatch(t, exp, builtBodies)
}

func TestXMLParamFinder_Find_Insert(t *testing.T) {
	t.Parallel()

	const payload = "/.git/HEAD"

	req := request.Request{Body: []byte(`<person sex="female"><firstname>Anna</firstname><lastname><first>Smith</first><second>Smith</second></lastname></person>`)}
	exp := [][]byte{
		[]byte(`<?xml version="1.0"?><per/.git/HEADson sex="female"><firstname>Anna</firstname><lastname><first>Smith</first><second>Smith</second></lastname></per/.git/HEADson>`),
		[]byte(`<?xml version="1.0"?><person s/.git/HEADex="female"><firstname>Anna</firstname><lastname><first>Smith</first><second>Smith</second></lastname></person>`),
		[]byte(`<?xml version="1.0"?><person sex="fem/.git/HEADale"><firstname>Anna</firstname><lastname><first>Smith</first><second>Smith</second></lastname></person>`),
		[]byte(`<?xml version="1.0"?><person sex="female"><firstname>Anna</firstname><last/.git/HEADname><first>Smith</first><second>Smith</second></last/.git/HEADname></person>`),
		[]byte(`<?xml version="1.0"?><person sex="female"><firstname>Anna</firstname><lastname><first>Smith</first><sec/.git/HEADond>Smith</sec/.git/HEADond></lastname></person>`),
		[]byte(`<?xml version="1.0"?><person sex="female"><firstname>Anna</firstname><lastname><first>Smith</first><second>Sm/.git/HEADith</second></lastname></person>`),
		[]byte(`<?xml version="1.0"?><person sex="female"><firstname>Anna</firstname><lastname><fi/.git/HEADrst>Smith</fi/.git/HEADrst><second>Smith</second></lastname></person>`),
		[]byte(`<?xml version="1.0"?><person sex="female"><firstname>Anna</firstname><lastname><first>Sm/.git/HEADith</first><second>Smith</second></lastname></person>`),
		[]byte(`<?xml version="1.0"?><person sex="female"><firs/.git/HEADtname>Anna</firs/.git/HEADtname><lastname><first>Smith</first><second>Smith</second></lastname></person>`),
		[]byte(`<?xml version="1.0"?><person sex="female"><firstname>An/.git/HEADna</firstname><lastname><first>Smith</first><second>Smith</second></lastname></person>`),
	}

	finder := entrypoint.NewXMLParamFinder()
	entrypoints := finder.Find(req)
	builtBodies := make([][]byte, 0, len(entrypoints))

	for _, e := range entrypoints {
		injReq := e.InjectPayload(req, profile.Insert, payload)
		builtBodies = append(builtBodies, injReq.Body)
	}

	assert.ElementsMatch(t, exp, builtBodies)
}
