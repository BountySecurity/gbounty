package profile

// InsertionPointType represents the type of insertion point.
type InsertionPointType string

// String returns the string representation of the insertion point type.
//
//nolint:gocyclo
func (i InsertionPointType) String() string {
	switch i {
	case ParamURLValue:
		return "Param URL Value"
	case ParamBodyValue:
		return "Param Body Value"
	case CookieValue:
		return "Cookie Value"
	case ParamXMLValue:
		return "Param XML Value"
	case ParamXMLAttrValue:
		return "Param XML Attr Value"
	case ParamMultiAttrValue:
		return "Param Multi Attr Value"
	case ParamJSONValue:
		return "Param JSON Value"
	case CookieName:
		return "Cookie Name"
	case ParamXMLName:
		return "Param XML Name"
	case URLPathFolder:
		return "URL Path Folder"
	case ParamURLName:
		return "Param URL Name"
	case ParamBodyName:
		return "Param Body Name"
	case EntireBodyXML:
		return "Entire Body XML"
	case URLPathFile:
		return "URL Path File"
	case ParamXMLAttrName:
		return "Param XML Attr Name"
	case ParamMultiAttrName:
		return "Param Multi Attr Name"
	case ParamJSONName:
		return "Param JSON Name"
	case MultiplePathDiscovery:
		return "Multiple Path Discovery"
	case SinglePathDiscovery:
		return "Single Path Discovery"
	case HeaderUserAgent:
		return "Header User Agent"
	case HeaderReferer:
		return "Header Referer"
	case HeaderOrigin:
		return "Header Origin"
	case HeaderHost:
		return "Header Host"
	case HeaderContentType:
		return "Header Content Type"
	case HeaderAccept:
		return "Header Accept"
	case HeaderAcceptLanguage:
		return "Header Accept Language"
	case HeaderAcceptEncoding:
		return "Header Accept Encoding"
	case HeaderNew:
		return "Header New"
	case EntireBody:
		return "Entire Body"
	case EntireBodyJSON:
		return "Entire Body JSON"
	case EntireBodyMulti:
		return "Entire Body Multi"
	default:
		return unknown
	}
}

const (
	ParamURLValue         InsertionPointType = "param_url"
	ParamBodyValue        InsertionPointType = "param_body"
	CookieValue           InsertionPointType = "param_cookie"
	ParamXMLValue         InsertionPointType = "param_xml"
	ParamXMLAttrValue     InsertionPointType = "param_xml_attr"
	ParamMultiAttrValue   InsertionPointType = "param_multipart_attr"
	ParamJSONValue        InsertionPointType = "param_json"
	CookieName            InsertionPointType = "param_name_cookie"
	ParamXMLName          InsertionPointType = "param_name_xml"
	URLPathFolder         InsertionPointType = "url_path_folder"
	ParamURLName          InsertionPointType = "param_name_url"
	ParamBodyName         InsertionPointType = "param_name_body"
	EntireBodyXML         InsertionPointType = "entire_body_xml"
	URLPathFile           InsertionPointType = "url_path_filename"
	ParamXMLAttrName      InsertionPointType = "param_name_xml_attr"
	ParamMultiAttrName    InsertionPointType = "param_name_multi_part_attr"
	ParamJSONName         InsertionPointType = "param_name_json"
	MultiplePathDiscovery InsertionPointType = "extension_provice"
	SinglePathDiscovery   InsertionPointType = "single_path_discovery"
	HeaderUserAgent       InsertionPointType = "user_agent"
	HeaderReferer         InsertionPointType = "referer"
	HeaderOrigin          InsertionPointType = "origin"
	HeaderHost            InsertionPointType = "host"
	HeaderContentType     InsertionPointType = "content_type"
	HeaderAccept          InsertionPointType = "accept"
	HeaderAcceptLanguage  InsertionPointType = "accept_language"
	HeaderAcceptEncoding  InsertionPointType = "accept_encoding"
	HeaderNew             InsertionPointType = "new_headers"
	EntireBody            InsertionPointType = "entire_body"
	EntireBodyJSON        InsertionPointType = "entire_body_json"
	EntireBodyMulti       InsertionPointType = "entire_body_multipart"
	UserProvided          InsertionPointType = "user_provided"
)

const (
	InsertionPointModeAny  InsertionPointMode = "any"
	InsertionPointModeSame InsertionPointMode = "same"
)

// InsertionPointMode represents the mode of the insertion point.
type InsertionPointMode string

// Any returns true if the insertion point mode is any.
func (ipm InsertionPointMode) Any() bool {
	return ipm == InsertionPointModeAny
}

// Same returns true if the insertion point mode is same.
func (ipm InsertionPointMode) Same() bool {
	return ipm == InsertionPointModeSame
}
