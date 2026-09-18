# Oracle Cloud box is aarch64 (Ampere); this base has arm64 wheels for
# pycryptodome and friends, so nothing has to compile.
FROM python:3.12-slim

WORKDIR /app

# Dependencies first so a code change does not re-resolve them.
COPY api/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY api/ ./api/

# Stamped by deploy/kia-deploy.sh. Last so a new commit does not invalidate the
# dependency layers above it - the whole point is that this changes every time.
ARG GIT_SHA=unknown
ENV KIA_GIT_SHA=$GIT_SHA

# ONE worker on purpose. Each gunicorn worker is its own process with its own
# VehicleManager, token and vehicle list, so N workers would mean N logins to
# Kia and N chances to trip its rate limiter - the exact thing moving off
# serverless is meant to fix. Threads give concurrency without that.
#
# The timeout is generous because a cold car genuinely takes tens of seconds
# to answer; it must stay above the clients' own 45s.
CMD ["gunicorn", \
     "--bind", "0.0.0.0:5000", \
     "--workers", "1", \
     "--threads", "8", \
     "--timeout", "120", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "api.index:app"]
