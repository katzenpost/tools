FROM golang:1.9 as builder
RUN mkdir -p /go/src/github.com/katzenpost
WORKDIR /go/src/github.com/katzenpost
RUN git clone https://github.com/katzenpost/authority
RUN git clone https://github.com/katzenpost/client
RUN git clone https://github.com/katzenpost/core
RUN git clone https://github.com/katzenpost/daemons
RUN git clone https://github.com/katzenpost/tools
RUN git clone https://github.com/katzenpost/docs
RUN git clone https://github.com/katzenpost/mailproxy
RUN git clone https://github.com/katzenpost/minclient
RUN git clone https://github.com/katzenpost/noise
RUN git clone https://github.com/katzenpost/server
WORKDIR /go/src/github.com/katzenpost/daemons
# install go dep
RUN go get -u github.com/golang/dep/cmd/dep
RUN git checkout voting_release
RUN dep ensure
WORKDIR /go/src/github.com/katzenpost/daemons/authority/nonvoting
RUN CGO_ENABLED=0 go install

# TODO: pick a base image that includes graphing, etc
FROM alpine:latest as authority
# install binaries
COPY --from=builder /go/bin/nonvoting .
CMD ["/nonvoting", "-f", "authority.toml"]
