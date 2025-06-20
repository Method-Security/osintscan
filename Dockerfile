FROM chromedp/headless-shell:129.0.6643.2 

ARG CLI_NAME="osintscan"
ARG TARGETARCH

RUN apt-get update && apt-get install -y ca-certificates git

# Setup Method Directory Structure
RUN \
  mkdir -p /opt/method/${CLI_NAME}/ && \
  mkdir -p /opt/method/${CLI_NAME}/var/data && \
  mkdir -p /opt/method/${CLI_NAME}/var/data/tmp && \
  mkdir -p /opt/method/${CLI_NAME}/var/conf && \
  mkdir -p /opt/method/${CLI_NAME}/var/log && \
  mkdir -p /opt/method/${CLI_NAME}/service/bin && \
  mkdir -p /mnt/output
  
COPY configs/                                /opt/method/${CLI_NAME}/var/conf/ 
COPY ${CLI_NAME}                             /opt/method/${CLI_NAME}/service/bin/${CLI_NAME}

RUN \
  adduser --disabled-password --gecos '' method && \
  chown -R method:method /opt/method/${CLI_NAME}/ && \
  chown -R method:method /mnt/output

USER method

WORKDIR /opt/method/${CLI_NAME}/

ENV PATH="/opt/method/${CLI_NAME}/service/bin:${PATH}"

ENTRYPOINT [ "osintscan" ]
