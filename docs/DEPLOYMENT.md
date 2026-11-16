# Deployment on Ubuntu VPS

## Prerequisites
- Ubuntu 22.04 or later, a domain name, and SSH access.
- Docker Engine with Compose plugin.
- DNS A/AAAA records pointing to the VPS.
- A model artifact trained and reviewed from a licensed dataset. Without one the app runs, but prediction returns 503.

## Prepare the release

Install Docker using its official Ubuntu instructions. Clone the project to a private deployment directory. Add the reviewed `artifacts/model/phishguard_model.joblib` and actual evaluation files; these are ignored by Git. Copy `.env.example` to `.env` and set an appropriate rate limit. Restrict file permissions on environment and model files.

Build and start:

```sh
docker compose up --build -d
docker compose ps
docker compose logs --tail=100 phishguard
curl -fsS http://127.0.0.1:8000/api/health
```

Compose publishes the container only on loopback. It runs as a non-root user with a read-only root filesystem, no added capabilities, resource limits, and an application health check. Keep port 8000 closed to public ingress.

## Caddy reverse proxy and automatic HTTPS

Install Caddy from its official package repository, then create a site configuration based on `deploy/Caddyfile.example`, replacing the example hostname with your domain. Validate and reload Caddy:

```sh
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

Allow inbound TCP 80 and 443 in the VPS firewall. Caddy obtains and renews certificates when public DNS and firewall routing are correct. Keep SSH restricted and apply Ubuntu and Docker security updates regularly.

## Nginx alternative

Use `deploy/nginx.conf.example` as a server block, configure your domain and certificate paths, then validate with `sudo nginx -t` and reload Nginx. Obtain certificates with an approved ACME client such as Certbot. Set request body and proxy timeouts conservatively.

## Operational security

- Do not enable public access to dataset or artifacts directories.
- Keep TLS termination at the reverse proxy and preserve localhost-only app binding.
- The API does not fetch submitted URLs. Keep this invariant in code review.
- The in-memory rate limiter is per worker. For multiple app workers/replicas, add a shared rate limiter before scaling.
- Review proxy logging policy; the application itself does not log the submitted URL, but proxies can be configured to capture request bodies.
- Back up model and evaluation artifacts securely. Rebuild from a trusted source rather than loading unknown Joblib files.
- Monitor health endpoint, CPU, memory, storage, and failed requests. Do not expose admin or debug endpoints.

