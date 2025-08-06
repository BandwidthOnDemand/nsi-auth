FROM python:3.13-alpine
WORKDIR /nsi_auth
COPY pyproject.toml .
RUN pip install .
COPY nsi_auth.py .
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "nsi_auth:app"]
