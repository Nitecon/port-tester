# Multi-stage build to keep runtime slim

ARG BASE=public.ecr.aws/docker/library/python:3.13-slim
# Stage 1: base runtime with Python only (no GUI deps needed)
FROM ${BASE} AS runtime

# Prevent Python from writing .pyc files and enable unbuffered logs
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Create app directory
WORKDIR /app

# Copy only the server script (GUI is not needed in container)
COPY server.py /app/server.py

# Expose common default ports (can override with -p)
EXPOSE 5000/tcp
EXPOSE 5001/udp

# Default entrypoint runs the headless echo server. Pass args at runtime, e.g.:
# docker run --rm -p 5000:5000 -p 5001:5001/udp nitecon/port-tester:latest \
#   --tcp-port 5000 --udp-port 5001
ENTRYPOINT ["python", "/app/server.py"]

# Default: no ports enabled. Users must pass --tcp-port/--udp-port.
CMD ["--tcp-port", "0", "--udp-port", "0"]
