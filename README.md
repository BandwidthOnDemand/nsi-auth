# NSI Authentication Server (`nsi-auth`)

[![Helm Chart](https://img.shields.io/badge/Helm%20Chart-available-blue)](https://github.com/workfloworchestrator/nsi-auth/pkgs/container/charts%2Fnsi-auth)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-compatible-brightgreen)](https://kubernetes.io/)
[![License](https://img.shields.io/badge/License-Apache%202.0-lightgrey.svg)](https://opensource.org/licenses/Apache-2.0)

The **NSI Authentication Server** (`nsi-auth`) integrates with Kubernetes ingress
controllers and gateways such as **ingress-nginx**, **Traefik** and **Envoy
Gateway**. It is an external authorization endpoint: the proxy forwards each
request's client-certificate identity to `nsi-auth`, which extracts the
**Distinguished Name (DN)** and verifies it against an allow-list using
standards-compliant **RFC 4514** comparison (via Python `cryptography`
`x509.Name`).

`nsi-auth` reads the identity from **one configurable header**
(`TLS_CLIENT_SUBJECT_AUTHN_HEADER`) and parses it with **one explicitly
configured codec** (`TLS_CLIENT_AUTHN_FORMAT`). The two are independent, so any
proxy / header combination works. There are two capabilities:

- **Compare a DN** that the proxy already extracted and put in a header, or
- **Extract the DN from a certificate** carried in a header.

| `TLS_CLIENT_AUTHN_FORMAT` | Reads | Typical proxy / header |
| --- | --- | --- |
| `dn-rfc2253`   | a DN string (RFC 2253)        | ingress-nginx `ssl-client-subject-dn`; Envoy Lua |
| `traefik-info` | DN inside `Subject="…"`        | Traefik `X-Forwarded-Tls-Client-Cert-Info` |
| `traefik-pem`  | Traefik minimized PEM (chain)  | Traefik `X-Forwarded-Tls-Client-Cert` |
| `pem`          | a standard (URL-encoded) PEM   | nginx `ssl-client-cert`; any proxy |
| `xfcc-cert`    | the PEM in XFCC `Cert=`         | Envoy `x-forwarded-client-cert` |
| `xfcc-subject` | the DN in XFCC `Subject=`       | Envoy `x-forwarded-client-cert` |

There is **no fallback between codecs**: if the configured source is missing or
unparseable, `nsi-auth` fails closed (**403**) rather than silently using a
different field.

- ✅ If the DN is authorized → **HTTP 200 (OK)** with `X-Auth-Method: mTLS` and `X-Client-DN: <RFC 4514 DN>` response headers
- ❌ Otherwise → **HTTP 403 (Forbidden)**

The proxy forwards these response headers to the upstream application via
`auth-response-headers` (nginx), `authResponseHeaders` (Traefik), or
`extAuth.http.headersToBackend` (Envoy Gateway), so downstream services (e.g.
nsi-dds-proxy) can confirm mTLS happened and identify the client.

---

## 📘 Table of Contents

- [Overview](#nsi-authentication-server-nsi-auth)
- [Installation and Configuration](#installation-and-configuration)
  - [1. Deploying `nsi-auth`](#1-deploying-nsi-auth)
  - [2. CA Certificate Handling](#2-ca-certificate-handling)
  - [3. Configuration Options](#3-configuration-options)
  - [4. Ingress Configuration](#4-ingress-configuration)
- [Versioning](#versioning)
- [See Also](#-see-also)

---

## Installation and Configuration

### 1. Deploying `nsi-auth`

`nsi-auth` is deployed via a Helm chart. The full list of configuration options
can be found in [`chart/values.yaml`](chart/values.yaml).

Below is an example configuration snippet:

```yaml
image:
  repository: ghcr.io/workfloworchestrator/nsi-auth
  pullPolicy: IfNotPresent
  tag: "latest"

service:
  type: ClusterIP
  port: 80
  targetPort: 8000

volumes:
  - name: config
    configMap:
      name: nsi-auth-config
      optional: false

volumeMounts:
  - name: config
    mountPath: "/config"
    readOnly: true

livenessProbe:
  httpGet:
    path: /health
    port: http
readinessProbe:
  httpGet:
    path: /health
    port: http

env:
  ALLOWED_CLIENT_SUBJECT_DN_PATH: "/config/allowed_client_dn.txt"
  TLS_CLIENT_SUBJECT_AUTHN_HEADER: "ssl-client-subject-dn"
  USE_WATCHDOG: "False"
  LOG_LEVEL: "INFO"

config:
  inlineData: |-
    allowed_client_dn.txt: |-
      CN=CertA,OU=Dept X,O=Company 1,C=NL
      CN=CertB,OU=Dept Y,O=Company 2,C=NL
      CN=CertC,OU=Dept Z,O=Company 3,C=NL
  additionalTrustedCA: ""
```
  
You can override default values by passing a custom values file:

```shell
helm upgrade --install --values my-values.yaml nsi-auth chart
```

> **Note:**
>
> The value `configMap.name` is defined as `{{ .Release.Name }}-config` and must match your Helm release name.
> In this example, the release name is nsi-auth.

Alternatively, install a published release directly from the registry. The chart
is an OCI artifact, so no `helm repo add` is needed:

```shell
helm upgrade --install --values my-values.yaml nsi-auth \
    oci://ghcr.io/workfloworchestrator/charts/nsi-auth --version <version>
```

The chart version equals the application version equals the git tag, so
`<version>` is the release tag you want to deploy. To inspect one first:

```shell
helm show chart oci://ghcr.io/workfloworchestrator/charts/nsi-auth --version <version>
```

### 2. CA Certificate Handling

During installation, a Kubernetes secret named `{{ .Release.Name }}-ca` is
automatically created.  This secret contains a `ca.crt` file, which includes:

- The list of CA certificates maintained by [cURL](https://curl.se/docs/caextract.html)
- Any additional certificates defined under `config.additionalTrustedCA`

This allows you to extend the trusted CA list with other certificates,
including self-signed CAs if needed.

The `ca.crt` secret is then used by the ingress controller to establish the
trusted CA chain (see [Ingress Configuration](#4-ingress-configuration)).

### 3. Configuration Options

| Variable                          | Description                                                                                                                                                                                                                                                                                         | Default                         |
| --------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------- |
| `ALLOWED_CLIENT_SUBJECT_DN_PATH`  | Path to the file listing allowed client certificate DNs. DNs should be as close to RFC 4514 format as possible, stored as UTF-8.                                                                                                                                                                    | `/config/allowed_client_dn.txt` |
| `TLS_CLIENT_SUBJECT_AUTHN_HEADER` | Name of the HTTP header carrying the client identity. Any header name; must match what the proxy sends.                                                                                                                                                                                             | `ssl-client-subject-dn`         |
| `TLS_CLIENT_AUTHN_FORMAT`         | Codec used to parse that header's value into a DN: `dn-rfc2253`, `traefik-info`, `traefik-pem`, `pem`, `xfcc-cert`, or `xfcc-subject` (see the table in the [Overview](#nsi-authentication-server-nsi-auth)). No fallback — a missing/unparseable source returns 403.                                  | `dn-rfc2253`                    |
| `USE_WATCHDOG`                    | Enables file-change monitoring using [watchdog](https://pypi.org/project/watchdog/). Useful for non-Kubernetes environments.                                                                                                                                                                        | `False`                         |
| `LOG_LEVEL`                       | Logging verbosity. Options: `DEBUG`, `INFO`, `WARNING`, `ERROR`.                                                                                                                                                                                                                                    | `INFO`                          |

**Health endpoint:**

`nsi-auth` exposes a `/health` endpoint that returns HTTP 200. This is used
for Kubernetes liveness and readiness probes, which are enabled by default in
the Helm chart:

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: http
readinessProbe:
  httpGet:
    path: /health
    port: http
```

**File reload behavior:**

By default, `nsi-auth` uses a simple polling mechanism (every 5 seconds) to
detect changes to the DN file.  If `USE_WATCHDOG` is enabled, the `watchdog`
module provides faster, event-based file monitoring.

> ⚠️ Note:
> `watchdog` cannot be used when running in Kubernetes, because ConfigMap updates replace the file via symbolic
> links, and this is not detected.

**DN format and comparison:**

DNs are parsed per RFC 4514 (via `cryptography.x509.Name`) and compared as
the multiset of (attribute-OID, value) pairs.

This makes matching independent of:

- **RDN ordering** — `CN=Foo,O=Acme,C=NL` and `C=NL,O=Acme,CN=Foo` are
  treated as the same identity.
- **Attribute-type spelling** — friendly names and dotted OIDs match each
  other (`emailAddress=` ≡ `1.2.840.113549.1.9.1=`, `GN=` ≡ `2.5.4.42=`,
  `SN=` ≡ `2.5.4.4=`, `organizationIdentifier=` ≡ `2.5.4.97=`). This is
  important because different reverse proxies serialize the same DN
  differently (e.g. Go's `cert.Subject.String()` falls back to dotted OIDs
  for any attribute type it doesn't have a friendly name for).

DNs in the allowed DN file should be as close to
[RFC 4514](https://datatracker.ietf.org/doc/html/rfc4514) format as possible
(e.g. `CN=CertA,OU=Dept X,O=Company 1,C=NL`). The file must be UTF-8
encoded.

### 4. Ingress Configuration

Finally, configure the ingress controller of the application to:

1. Use the `ca.crt` secret created by `nsi-auth`
2. Enable and verify **mutual TLS (mTLS)** authentication
3. Forward the client certificate DN (or certificate) to `nsi-auth` for validation

#### ingress-nginx

Keep the defaults `TLS_CLIENT_SUBJECT_AUTHN_HEADER: ssl-client-subject-dn` and
`TLS_CLIENT_AUTHN_FORMAT: dn-rfc2253`.

Assuming `nsi-auth` is deployed in the `production` namespace, use the
following ingress annotations:

```yaml
nginx.ingress.kubernetes.io/auth-tls-secret: production/nsi-auth-ca
nginx.ingress.kubernetes.io/auth-tls-verify-client: "on"
nginx.ingress.kubernetes.io/auth-tls-verify-depth: "3"
nginx.ingress.kubernetes.io/auth-url: http://nsi-auth.production.svc.cluster.local/validate
```

#### Traefik

To forward the full PEM certificate (or chain), set:

```yaml
TLS_CLIENT_SUBJECT_AUTHN_HEADER: X-Forwarded-Tls-Client-Cert
TLS_CLIENT_AUTHN_FORMAT: traefik-pem
```

and enable the Traefik
[PassTLSClientCert](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/passtlsclientcert/)
middleware with `pem: true`:

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: nsi-auth-mtls
spec:
  passTLSClientCert:
    pem: true
```

Alternatively, use the cert-info summary header — set
`TLS_CLIENT_SUBJECT_AUTHN_HEADER: X-Forwarded-Tls-Client-Cert-Info` and
`TLS_CLIENT_AUTHN_FORMAT: traefik-info`, and configure the `info.subject` fields
in the middleware.

#### Envoy Gateway

Envoy Gateway has no built-in "subject DN" header. The recommended approach
mirrors ingress-nginx: inject the DN with a small Lua filter and keep the
defaults (`ssl-client-subject-dn` + `dn-rfc2253`). A best-current-practice
deployment (here `nsi-auth` and the protected app are in `production`) is four
resources:

**1. Terminate mTLS on the listener** — `ClientTrafficPolicy` validates the
client certificate against the `nsi-auth` CA secret:

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: ClientTrafficPolicy
metadata:
  name: my-app-mtls
  namespace: production
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: Gateway
      name: my-gateway
      sectionName: https-my-app          # the listener serving the app's host
  tls:
    clientValidation:
      caCertificateRefs:
        - kind: Secret
          group: ""
          name: nsi-auth-ca              # the {{ .Release.Name }}-ca secret
      mode: RequireAndVerify
```

**2. Copy the cert subject DN into the header** — `EnvoyExtensionPolicy` (Lua),
targeting the app's `HTTPRoute`. It strips any client-supplied value first, so a
valid cert-holder cannot assert a different DN:

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: EnvoyExtensionPolicy
metadata:
  name: my-app-client-cert
  namespace: production
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      name: my-app
  lua:
    - type: Inline
      inline: |
        function envoy_on_request(request_handle)
          request_handle:headers():remove("ssl-client-subject-dn")
          local dsc = request_handle:streamInfo():downstreamSslConnection()
          if dsc ~= nil and dsc:peerCertificatePresented() then
            local subject = dsc:subjectPeerCertificate()   -- RFC 2253
            if subject ~= nil and subject ~= "" then
              request_handle:headers():add("ssl-client-subject-dn", subject)
            end
          end
        end
```

`subjectPeerCertificate()` returns the DN in RFC 2253 — the same format
ingress-nginx emits — so `nsi-auth` parses it with `dn-rfc2253`.

**3. Run Lua before ext_authz** — otherwise the header is not set when the auth
subrequest fires. Configure the `EnvoyProxy` referenced by your `GatewayClass`:

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: EnvoyProxy
metadata:
  name: my-proxy
  namespace: production
spec:
  filterOrder:
    - name: envoy.filters.http.lua
      before: envoy.filters.http.ext_authz
```

**4. Delegate authorization to nsi-auth** — `SecurityPolicy` forwards the DN
header to `/validate` and passes the response headers on to the app:

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: SecurityPolicy
metadata:
  name: my-app-security-policy
  namespace: production
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      name: my-app
  extAuth:
    headersToExtAuth:
      - ssl-client-subject-dn            # the Lua-set DN reaches nsi-auth
    http:
      backendRef:
        kind: Service
        name: nsi-auth
        namespace: production
        port: 80
      pathOverride: /validate
      headersToBackend:
        - X-Auth-Method
        - X-Client-DN
```

> ⚠️ Envoy's ext_authz mirrors the **downstream request method** onto the
> `/validate` subrequest (it does not force GET). `nsi-auth` accepts any method on
> `/validate` for this reason; do not reverse that, or every POST to a protected
> backend is rejected by the auth step.

**Alternative — forward the certificate via XFCC.** Instead of the Lua filter,
make Envoy emit the cert in `x-forwarded-client-cert` by setting
`set_current_client_cert_details.cert: true` (with
`forward_client_cert_details: SANITIZE_SET`) via an `EnvoyPatchPolicy`, then set
`TLS_CLIENT_SUBJECT_AUTHN_HEADER: x-forwarded-client-cert` and
`TLS_CLIENT_AUTHN_FORMAT: xfcc-cert` (or `xfcc-subject` for the `Subject=`
field). The Lua approach needs no raw-config patch, so it is preferred.

#### Result

These settings ensure that the ingress controller:

- Validates client certificates against the trusted CA chain
- Delegates authorization to the nsi-auth service

---

## Versioning

The release git tag is the only place a version is written by hand. `pyproject.toml` declares
`dynamic = ["version"]` and setuptools-scm derives it: a tag builds `0.3.2`, any other commit builds
the next patch as a dev release with its commit, `0.3.3.dev3+g1a2b3c4`.

The container build has no `.git`, so `.github/workflows/build-push-container.yml` checks out with
`fetch-depth: 0`, resolves the version on the runner, and passes it as `--build-arg VERSION=...`,
which the `Dockerfile` hands to setuptools-scm as `SETUPTOOLS_SCM_PRETEND_VERSION_FOR_NSI_AUTH`. A
build without that argument fails rather than producing a mislabelled image:

```bash
docker build --build-arg VERSION="$(uvx --from setuptools-scm python -m setuptools_scm)" -t nsi-auth .
```

---

📄 License

This project is licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).

---

🧠 See Also

- [Kubernetes Ingress documentation](https://kubernetes.io/docs/concepts/services-networking/ingress/)
- [Nginx Ingress Controller](https://kubernetes.github.io/ingress-nginx/)
- [Traefik PassTLSClientCert middleware](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/passtlsclientcert/)
- [Envoy Gateway](https://gateway.envoyproxy.io/)
- [cURL CA Certificates](https://curl.se/docs/caextract.html)
