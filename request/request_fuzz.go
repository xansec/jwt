package request

import (
	"fmt"
	"net/http"
	"net/url"
	//"reflect"
	"strings"
	"github.com/golang-jwt/jwt/v4"
	"github.com/golang-jwt/jwt/v4/test"
)

type requestData struct {
	name      string
	claims    jwt.MapClaims
	extractor Extractor
	headers   map[string]string
	query     url.Values
	valid     bool
}

func FuzzRequest(data []byte) int {
	var requestFuzzData requestData
	if len(data) < 64 {
		return -1
	}
	requestFuzzData.name = string(data[0:15])
	requestFuzzData.claims = jwt.MapClaims{string(data[16:23]): string(data[24:31])}
	requestFuzzData.extractor = OAuth2Extractor
	requestFuzzData.headers = map[string]string{"Authorization": "Bearer %v"}
	requestFuzzData.query = url.Values{}
	requestFuzzData.valid = true

	// load keys from disk
	privateKey := test.LoadRSAPrivateKeyFromDisk("/jwt/test/sample_key")
	publicKey := test.LoadRSAPublicKeyFromDisk("/jwt/test/sample_key.pub")
	keyfunc := func(*jwt.Token) (interface{}, error) {
		return publicKey, nil
	}


	// Make token from claims
	tokenString := test.MakeSampleToken(requestFuzzData.claims, jwt.SigningMethodRS256, privateKey)

	// Make query string
	for k, vv := range requestFuzzData.query {
		for i, v := range vv {
			if strings.Contains(v, "%v") {
				requestFuzzData.query[k][i] = fmt.Sprintf(v, tokenString)
			}
		}
	}

	// Make request from test struct
	r, _ := http.NewRequest("GET", fmt.Sprintf("/?%v", requestFuzzData.query.Encode()), nil)
	for k, v := range requestFuzzData.headers {
		if strings.Contains(v, "%v") {
			r.Header.Set(k, fmt.Sprintf(v, tokenString))
		} else {
			r.Header.Set(k, tokenString)
		}
	}
	//token, err := ParseFromRequestWithClaims(r, requestFuzzData.extractor, jwt.MapClaims{}, keyfunc)
	ParseFromRequestWithClaims(r, requestFuzzData.extractor, jwt.MapClaims{}, keyfunc)
/***
	if token == nil {
		error := fmt.Sprint("[%v] Token was not found: %v", requestFuzzData.name, err)
		println(error)
	}
	if !reflect.DeepEqual(requestFuzzData.claims, token.Claims) {
		error := fmt.Sprint("[%v] Claims mismatch. Expecting: %v  Got: %v", requestFuzzData.name, requestFuzzData.claims, token.Claims)
		println(error)
	}
	if requestFuzzData.valid && err != nil {
		error := fmt.Sprint("[%v] Error while verifying token: %v", requestFuzzData.name, err)
		println(error)
	}
	if !requestFuzzData.valid && err == nil {
		error := fmt.Sprint("[%v] Invalid token passed validation", requestFuzzData.name)
		println(error)
	}
***/
	return 1
}
