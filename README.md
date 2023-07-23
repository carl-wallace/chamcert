# chamcert

Work-in-progress utility to generate artifacts containing a [deltaCertificateDescriptor](https://datatracker.ietf.org/doc/html/draft-bonnell-lamps-chameleon-certs-01) extension and to parse
artifacts containing the extension and reconstruct a certificate from the extension.

At present, base certificates can be generated and parsed, with the 
reconstructed certificate compared to a reference value. TODO items include support for
certificate verification, and CSR generation.

A sample invocation of the tool is below. The first command takes a CA key, a CA cert, a delta cert and a destination to receive a base certificate. The second takes a reference (same as delta in first command) and a base from which to reconstruct a cert to compare to the reference.

```bash
$ ./target/release/chamcert -k tests/artifacts/GoodCACert.key -c tests/artifacts/GoodCACert.crt -d ./tests/artifacts/ValidCertificatePathTest1EE.crt -b ./tests/artifacts/base.der
-----BEGIN CERTIFICATE-----
MIIC5zCCAo2gAwIBAgIUAclLovvSjnUnkQ6z4YGLBSNN7ocwCgYIKoZIzj0EAwIw
QDELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTEx
EDAOBgNVBAMTB0dvb2QgQ0EwHhcNMjMwNzIyMTgxODIzWhcNMzMwNzE5MTgxODIz
WjBTMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAx
MTEjMCEGA1UEAxMaVmFsaWQgRUUgQ2VydGlmaWNhdGUgVGVzdDEwWTATBgcqhkjO
PQIBBggqhkjOPQMBBwNCAASZu8sXNr8/0rrW1o2u5iOXRQmOEbUNXFhx7MIfHoAB
mZ4OpY5HbzIxjsKRgpJy63m/ky5F3bBSSczrX5C3ZAG0o4IBUDCCAUwwIAYDVR0j
BBkwF4AVWAGEJBu8K1KUSj2lEHIUUfWvOsn/MB4GA1UdDgQXBBWoPAmdZ/bYR7qi
0PwYclaIQG2Vlf8wDgYDVR0PAQH/BAQDAgTwMBcGA1UdIAQQMA4wDAYKYIZIAWUD
AgEwATCB3gYKYIZIAYb6a1AGAQEB/wSBzDCByQIBAaIeFw0xMDAxMDEwODMwMDBa
Fw0zMDEyMzEwODMwMDBaMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgpDqvMZE
JqMmB09BAKnp9Ixgnhl8w/6yuArKg1JULZ1j1MIjU0CG1sLnMNlfkAzBIac7ScMt
7NK+vPTEg46ZBgNJADBGAiEAo4HCOqnPyMxfr5LGEopLfMfnpn3UhGfBjz+jK5cf
pVgCIQCwAUyA/7CIDxe3xm3wlk3MHJcvc3+crC5YjkktI0opzjAKBggqhkjOPQQD
AgNIADBFAiEAzzNlyA79vYx4sY9qjSKtAPUN+UpmrIebm0A9dRy4FwECIAKm5Ts1
5vkZqG/mJMdHTBJM8VuHMSHSB9gs/+mpvSkN
-----END CERTIFICATE-----

$ ./target/release/chamcert -r ./tests/artifacts/ValidCertificatePathTest1EE.crt -v ./tests/artifacts/base.der
Reconstructed certificate matches the reference.
```

The gencsrs.sh script (and corresponding output) shows how to exercise the 100% untested CSR generation support.
