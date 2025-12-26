FROM golang:1.23-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /app
COPY go.mod main.go ./
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -o /temporal-server .

FROM temporalio/auto-setup:1.26.3.0

USER root
RUN echo '#!/bin/bash' > /etc/temporal/start-temporal.sh && \
    echo 'exec /usr/local/bin/temporal-custom' >> /etc/temporal/start-temporal.sh && \
    chmod +x /etc/temporal/start-temporal.sh
USER temporal

COPY --from=builder /temporal-server /usr/local/bin/temporal-custom

ENTRYPOINT ["/etc/temporal/entrypoint.sh"]
CMD ["autosetup"]