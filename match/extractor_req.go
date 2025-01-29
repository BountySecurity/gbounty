package match

import (
	"github.com/BountySecurity/gbounty/request"
)

func reqBytesToFindInAll(where string, req *request.Request) (int, []byte) {
	switch where {
	case "All request":
		return 0, req.Bytes()
	case "All parameters name":
		return 0, reqParamNameBytes(req)
	case "All parameters value":
		return 0, reqParamValueBytes(req)
	case "All HTTP headers value":
		return 0, req.HeaderBytes()
	}

	return 0, []byte{}
}

func reqBytesToFindInURL(where string, req *request.Request) (int, []byte) {
	switch where {
	case "Url path folder":
		return 0, reqURLFolderBytes(req)
	case "Url path filename":
		return 0, reqURLFileBytes(req)
	}

	return 0, []byte{}
}

func reqBytesToFindInParam(where string, req *request.Request) (int, []byte) {
	switch where {
	case "Param url name":
		return 0, reqQueryNameBytes(req)
	case "Param url value":
		return 0, reqQueryValueBytes(req)
	case "Param body name":
		return 0, reqBodyNameBytes(req)
	case "Param body value":
		return 0, reqBodyValueBytes(req)
	case "Param cookie name":
		return 0, reqCookieNameBytes(req)
	case "Param cookie value":
		return 0, reqCookieValueBytes(req)
	case "Param json name":
		return 0, reqJSONNameBytes(req)
	case "Param json value":
		return 0, reqJSONValueBytes(req)
	case "Param xml name":
		return 0, reqXMLNameBytes(req)
	case "Param xml value":
		return 0, reqXMLValueBytes(req)
	case "Param xml attr name":
		return 0, reqXMLAttrNameBytes(req)
	case "Param xml attr value":
		return 0, reqXMLAttrValueBytes(req)
	case "Param multipart attr name":
		return 0, reqMultipartNameBytes(req)
	case "Param multipart attr value":
		return 0, reqMultipartValueBytes(req)
	}

	return 0, []byte{}
}

func reqBytesToFindInEntire(where string, req *request.Request) (int, []byte) {
	switch where {
	case "Entire body":
		return 0, req.Body
	case "Entire body xml":
		return 0, reqBodyXMLBytes(req)
	case "Entire body json":
		return 0, reqBodyJSONBytes(req)
	case "Entire body multipart":
		return 0, reqBodyMultipartBytes(req)
	}

	return 0, []byte{}
}

func reqBytesToFindInHTTP(where string, req *request.Request) (int, []byte) {
	switch where {
	case "HTTP host header":
		return 0, []byte(req.Header("Host"))
	case "HTTP user agent header":
		return 0, []byte(req.Header("User-Agent"))
	case "HTTP content type header":
		return 0, []byte(req.Header("Content-Type"))
	case "HTTP referer header":
		return 0, []byte(req.Header("Referer"))
	case "HTTP origin header":
		return 0, []byte(req.Header("Origin"))
	case "HTTP accept encoding header":
		return 0, []byte(req.Header("Accept-Encoding"))
	case "HTTP accept header":
		return 0, []byte(req.Header("Accept"))
	case "HTTP accept language header":
		return 0, []byte(req.Header("Accept-Language"))
	}

	return 0, []byte{}
}

func reqParamNameBytes(req *request.Request) []byte {
	bodyNameBytes := reqBodyNameBytes(req)
	cookieNameBytes := reqCookieNameBytes(req)
	jsonNameBytes := reqJSONNameBytes(req)
	multipartNameBytes := reqMultipartNameBytes(req)
	queryNameBytes := reqQueryNameBytes(req)
	xmlNameBytes := reqXMLNameBytes(req)
	xmlAttrNameBytes := reqXMLAttrNameBytes(req)

	totalLen := len(bodyNameBytes) + len(cookieNameBytes) + len(jsonNameBytes) +
		len(multipartNameBytes) + len(queryNameBytes) + len(xmlNameBytes) + len(xmlAttrNameBytes)

	paramNameBytes := make([]byte, 0, totalLen)

	for _, b := range [][]byte{
		bodyNameBytes,
		cookieNameBytes,
		jsonNameBytes,
		multipartNameBytes,
		queryNameBytes,
		xmlNameBytes,
		xmlAttrNameBytes,
	} {
		paramNameBytes = append(paramNameBytes, b...)
	}

	return paramNameBytes
}

func reqParamValueBytes(req *request.Request) []byte {
	bodyValueBytes := reqBodyValueBytes(req)
	cookieValueBytes := reqCookieValueBytes(req)
	jsonValueBytes := reqJSONValueBytes(req)
	multipartValueBytes := reqMultipartValueBytes(req)
	queryValueBytes := reqQueryValueBytes(req)
	xmlValueBytes := reqXMLValueBytes(req)
	xmlAttrValueBytes := reqXMLAttrValueBytes(req)

	totalLen := len(bodyValueBytes) + len(cookieValueBytes) + len(jsonValueBytes) +
		len(multipartValueBytes) + len(queryValueBytes) + len(xmlValueBytes) + len(xmlAttrValueBytes)

	paramValueBytes := make([]byte, 0, totalLen)

	for _, b := range [][]byte{
		bodyValueBytes,
		cookieValueBytes,
		jsonValueBytes,
		multipartValueBytes,
		queryValueBytes,
		xmlValueBytes,
		xmlAttrValueBytes,
	} {
		paramValueBytes = append(paramValueBytes, b...)
	}

	return paramValueBytes
}
