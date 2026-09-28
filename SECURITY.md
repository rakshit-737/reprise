# Security policy

## Scope

REPRISE is an experimental Kubernetes security investigation project. The
current release is read-only with respect to clusters and uses synthetic demo
data.

Do not upload real credentials, Secret values, production audit bodies, or
private cluster data to this repository or its issue tracker.

## Reporting a vulnerability

Please do not disclose a suspected vulnerability in a public issue. Use a
private GitHub security advisory for this repository once enabled, or contact
the repository owner privately through GitHub with:

- affected version or commit;
- reproduction steps using only synthetic/local data;
- impact and required permissions;
- suggested mitigation, if known.

Do not test against public systems or clusters you do not own or have explicit
authorization to assess.

## Development security boundary

- The default profile rejects Secret and token material.
- The investigator has no arbitrary shell, SQL, URL, or Kubernetes tool.
- Approval records are local and unauthenticated; they are not production
  authorization.
- No cluster mutation executor is included in the current release.
