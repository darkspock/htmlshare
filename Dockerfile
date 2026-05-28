FROM node:24-alpine AS web-build
WORKDIR /src/web/app
COPY web/app/package.json web/app/package-lock.json ./
RUN npm ci
COPY web/app ./
RUN npm run build

FROM golang:1.26-alpine AS go-build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web-build /src/web/app/dist ./web/app/dist
RUN go build -o /out/htmlshare ./cmd/htmlshare
RUN go build -o /out/htmlshare-mcp ./cmd/htmlshare-mcp

FROM alpine:3.22
WORKDIR /app
RUN adduser -D -u 10001 htmlshare
COPY --from=go-build /out/htmlshare /usr/local/bin/htmlshare
COPY --from=go-build /out/htmlshare-mcp /usr/local/bin/htmlshare-mcp
COPY web/home ./web/home
COPY --from=web-build /src/web/app/dist ./web/app/dist
USER htmlshare
EXPOSE 4545
CMD ["htmlshare"]
