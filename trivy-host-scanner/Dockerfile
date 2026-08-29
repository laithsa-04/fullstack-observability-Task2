FROM aquasec/trivy:0.65.0

RUN apk add --no-cache bash jq
COPY scan-host.sh /usr/local/bin/scan-host.sh
RUN chmod +x /usr/local/bin/scan-host.sh

ENTRYPOINT ["/usr/local/bin/scan-host.sh"]
