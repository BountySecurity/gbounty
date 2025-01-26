package encode

import (
	"encoding/base64"
	"fmt"
	"strings"
)

func URL(payload string) string {
	var sBuilder strings.Builder

	for _, c := range payload {
		_, _ = sBuilder.WriteString(fmt.Sprintf("%%%x", c))
	}

	return sBuilder.String()
}

func UnicodeURL(payload string) string {
	var sBuilder strings.Builder

	for _, c := range payload {
		_, _ = sBuilder.WriteString(fmt.Sprintf("%%u00%x", c))
	}

	return sBuilder.String()
}

func HTML(payload string) string {
	var sBuilder strings.Builder

	for _, c := range payload {
		_, _ = sBuilder.WriteString(fmt.Sprintf("&#x%x;", c))
	}

	return sBuilder.String()
}

func KeyHTML(payload string) string {
	var sBuilder strings.Builder

	const key = "\\<\\(\\[\\\\\\^\\-\\=\\$\\!\\|\\]\\)\\?\\*\\+\\.\\>]\\&\\%\\:\\@ "

	for _, c := range payload {
		if strings.Contains(key, string(c)) {
			_, _ = sBuilder.WriteString(fmt.Sprintf("&#x%x;", c))
		} else {
			_, _ = sBuilder.WriteRune(c)
		}
	}

	return sBuilder.String()
}

func KeyURL(payload string) string {
	var sBuilder strings.Builder

	const key = "\\<\\(\\[\\\\\\^\\-\\=\\$\\!\\|\\]\\)\\?\\*\\+\\.\\>]\\&\\%\\:\\@ "

	for _, c := range payload {
		if strings.Contains(key, string(c)) {
			_, _ = sBuilder.WriteString(fmt.Sprintf("%%%x", c))
		} else {
			_, _ = sBuilder.WriteRune(c)
		}
	}

	return sBuilder.String()
}

func TheseURL(payload, chars string) string {
	var sBuilder strings.Builder

	for _, c := range payload {
		if strings.Contains(chars, string(c)) {
			_, _ = sBuilder.WriteString(fmt.Sprintf("%%%x", c))
		} else {
			_, _ = sBuilder.WriteRune(c)
		}
	}

	return sBuilder.String()
}

func Base64(payload string) string {
	return base64.StdEncoding.EncodeToString([]byte(payload))
}
