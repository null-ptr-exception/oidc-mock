FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /oidc-mock .

FROM scratch
COPY --from=build /oidc-mock /oidc-mock
ENTRYPOINT ["/oidc-mock"]
