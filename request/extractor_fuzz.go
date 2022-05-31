package request

import (
	"fmt"
	"net/http"
	"net/url"
)

type extractorData struct {
	name      string
	extractor Extractor
	headers   map[string]string
	query     url.Values
	token     string
	err       error
}

func FuzzExtractor(data []byte) int {
	fuzzToken := string(data[:])
  var extractorFuzzData extractorData;
  extractorFuzzData.name = "filter"
  extractorFuzzData.extractor = AuthorizationHeaderExtractor
  extractorFuzzData.headers = map[string]string{"Authorization": "Bearer " + fuzzToken}
  extractorFuzzData.query = nil
  extractorFuzzData.token = fuzzToken
  extractorFuzzData.err = nil
	// Make request from test struct
	r := makeExampleRequest("GET", "/", extractorFuzzData.headers, extractorFuzzData.query)
	// Test extractor
	token, err := extractorFuzzData.extractor.ExtractToken(r)
	if token != extractorFuzzData.token {
		error := fmt.Sprintf("[%v] Expected token '%v'.  Got '%v'", extractorFuzzData.name, extractorFuzzData.token, token)
		panic(error)
	}
	if err != extractorFuzzData.err {
		error := fmt.Sprintf("[%v] Expected error '%v'.  Got '%v'", extractorFuzzData.name, extractorFuzzData.err, err)
		panic(error)
	}
	return 1
}

func makeExampleRequest(method, path string, headers map[string]string, urlArgs url.Values) *http.Request {
	r, _ := http.NewRequest(method, fmt.Sprintf("%v?%v", path, urlArgs.Encode()), nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}
