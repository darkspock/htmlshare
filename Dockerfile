FROM --platform=$BUILDPLATFORM node:24-alpine AS web-build
WORKDIR /src/web/app
COPY web/app/package.json web/app/package-lock.json ./
RUN npm ci
COPY web/app ./
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS go-build
WORKDIR /src
ARG TARGETOS
ARG TARGETARCH
RUN apk add --no-cache ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web-build /src/web/app/dist ./web/app/dist
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/htmlshare ./cmd/htmlshare
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/htmlshare-mcp ./cmd/htmlshare-mcp

FROM scratch
WORKDIR /app
COPY --from=go-build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=go-build /out/htmlshare /usr/local/bin/htmlshare
COPY --from=go-build /out/htmlshare-mcp /usr/local/bin/htmlshare-mcp
COPY web/home ./web/home
COPY --from=web-build /src/web/app/dist ./web/app/dist
USER 10001:10001
EXPOSE 4545
CMD ["htmlshare"]
