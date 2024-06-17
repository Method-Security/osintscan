# Basic Usage

## Binaries

Running as a binary allows you to skip dealing with any container related networking issues and leverage the same network interface that the host machine is using.

You can validate that the binary is working by scanning the publicly available `scanme.sh`.

```bash
networkscan portscan --topports 100 --target scanme.sh
```

## Docker

Running networkscan within a Docker container should typically work similarly to running directly on a host, however, occasionally there are a few things to keep in mind.

If you're running on a Docker container on a MacOS machine and you are trying to scan a locally running service, you can leverage the `host.docker.internal` address as mentioned in the Docker documentation [here](https://docs.docker.com/desktop/networking/#i-want-to-connect-from-a-container-to-a-service-on-the-host).

```bash
docker run ghcr.io/method-security/networkscan \
  portscan \
  --topports 100 \
  --target scanme.sh
```
