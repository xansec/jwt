FROM fuzzers/go-fuzz as builder

ADD . /
WORKDIR /request
RUN go-fuzz-build -libfuzzer -o extracto
RUN go-fuzz-build -libfuzzer -o extractor_fuzz.a -func FuzzExtractor
RUN go-fuzz-build -libfuzzer -o request_fuzz.a -func FuzzRequest
RUN clang -fsanitize=fuzzer,address extractor_fuzz.a -o extractor_fuzz.libfuzzer
RUN clang -fsanitize=fuzzer,address request_fuzz.a -o request_fuzz.libfuzzer

FROM ubuntu
COPY --from=builder /request/request_fuzz.libfuzzer /request_fuzz
COPY --from=builder /request/extractor_fuzz.libfuzzer /extractor_fuzz
