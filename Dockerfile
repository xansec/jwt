FROM golang:1.17.10 as builder
#FROM fuzzers/go-fuzz:1.2.0 as builder

RUN apt update -y && DEBIAN_FRONTEND=disabled apt install -y clang

RUN go install github.com/dvyukov/go-fuzz/go-fuzz@latest github.com/dvyukov/go-fuzz/go-fuzz-build@latest
RUN mkdir /go/jwt
ADD . /go/jwt
WORKDIR /go/jwt
RUN go mod tidy

WORKDIR /go/jwt/request
RUN go get -u github.com/dvyukov/go-fuzz/go-fuzz@latest 
RUN go get -u github.com/dvyukov/go-fuzz/go-fuzz-build@latest
RUN go get -u github.com/dvyukov/go-fuzz/go-fuzz-dep
RUN go-fuzz-build -libfuzzer -o extractor_fuzz.a -func FuzzExtractor
RUN go-fuzz-build -libfuzzer -o request_fuzz.a -func FuzzRequest
RUN clang -fsanitize=fuzzer,address extractor_fuzz.a -o extractor_fuzz.libfuzzer
RUN clang -fsanitize=fuzzer,address request_fuzz.a -o request_fuzz.libfuzzer

FROM ubuntu
RUN mkdir /jwt
RUN mkdir /jwt/fuzz
COPY --from=builder /go/jwt/request/request_fuzz.libfuzzer /jwt/fuzz/request_fuzz
COPY --from=builder /go/jwt/request/extractor_fuzz.libfuzzer /jwt/fuzz/extractor_fuzz
COPY --from=builder /go/jwt/test /jwt/test
