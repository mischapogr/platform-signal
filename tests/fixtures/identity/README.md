# Synthetic identity qualification

`scripts/check-access-idp.py` generates a fresh synthetic Keycloak realm, four
users, three confidential clients, PKCE callbacks, private policy, credentials
and a short-lived TLS authority for each run. Nothing here is a deployable
company realm or production credential. Generated credentials live only in a
mode0700 temporary directory outside artifact trees. Successful confirmed cleanup
removes it; uncertain cleanup retains an exact private recovery reference.

The pinned optional test image and locked tools are described in
[local IdP qualification](../../../docs/43-local-idp-qualification.md). The real
browser/SDK flow supplies actual IdP access tokens to the unchanged monolith and
existing console. It adds no SIGNAL login server or mandatory identity service.
