FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/threatlens-api .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/threatlens-api /threatlens-api
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/threatlens-api"]
