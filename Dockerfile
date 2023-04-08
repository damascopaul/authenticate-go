# BUILD stage
FROM golang:1.19-alpine as build
WORKDIR /build

COPY . .

RUN go build -o app

# RUN stage
FROM golang:1.19-alpine
WORKDIR /app

COPY --from=build /build/app .

EXPOSE 8080
CMD [ "./app" ]
