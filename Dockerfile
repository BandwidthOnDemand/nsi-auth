FROM python:3.13-alpine
ARG VERSION
ENV SETUPTOOLS_SCM_PRETEND_VERSION_FOR_NSI_AUTH=${VERSION}
WORKDIR /nsi_auth
COPY pyproject.toml .
RUN pip --no-cache-dir install .
COPY nsi_auth.py rfc4514_cmp.py ./
CMD ["uvicorn", "--host", "0.0.0.0", "--port", "8000", "--interface", "wsgi", "nsi_auth:app"]
