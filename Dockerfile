# The redactor as an HTTP service.
#   docker build -t redactor:0.1.0 .
#   docker run -p 8080:8080 -v "$PWD/rules.yaml:/etc/redactor/rules.yaml:ro" redactor:0.1.0

# Official slim Python image (Debian without extras). The exact version is pinned, so every
# build starts from the same base and matches the Python the tests ran on.
FROM python:3.12.7-slim-bookworm

# No .pyc files (the filesystem is read-only in Kubernetes anyway), and unbuffered output so
# log lines show up in `docker logs` / `kubectl logs` right away.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Only what the service needs: no tests, no git history, no notes (see .dockerignore).
COPY pyproject.toml ./
COPY redactor/ redactor/
RUN pip install --no-cache-dir . \
    && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin redactor

# Never run as root: if the process were ever taken over, it would have no privileges.
USER 10001

EXPOSE 8080

# The rules are not baked in: Kubernetes mounts them from a ConfigMap at this path. If they
# are missing or invalid, the process exits with code 2 instead of starting (fail closed).
ENTRYPOINT ["redactor"]
CMD ["--serve", "--addr", ":8080", "--rules", "/etc/redactor/rules.yaml"]
