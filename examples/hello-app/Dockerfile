FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/hello-app .

FROM alpine:3.21
WORKDIR /app
COPY --from=build /out/hello-app /app/hello-app
COPY static /app/static
EXPOSE 3000
ENTRYPOINT ["/app/hello-app"]
