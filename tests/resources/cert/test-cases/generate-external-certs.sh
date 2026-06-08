#!/usr/bin/env bash
#
# Regenerates the certs used in test fixtures. A throwaway CA plus two client certificates.
#
# The CA key is intentionally discarded. Each run regenerates the whole set.
#
# Add a fixture by calling gen() with an output name and an X.509 subject, e.g.:

#   gen ext-client "/DC=bar/DC=foo/CN=extuser"
#
# The subject's RDNs are reversed into an LDAP DN by SubjectDnCredentialMapper.
#
set -euo pipefail
cd "$(dirname "$0")"

openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout ext-ca.key -out ext-ca.crt -days 36500 \
    -subj "/CN=FreeDSx Test External CA"

gen() {
    local name="$1" subject="$2"
    openssl req -newkey rsa:2048 -nodes -keyout "${name}.key" -out "${name}.csr" -subj "$subject"
    openssl x509 -req -in "${name}.csr" -CA ext-ca.crt -CAkey ext-ca.key -CAcreateserial \
        -days 36500 -out "${name}.crt"
    rm -f "${name}.csr"
}

# Subjects reverse (via SubjectDnCredentialMapper) to cn=extuser,dc=foo,dc=bar (a seeded entry)
# and cn=nobody,dc=foo,dc=bar (which is not seeded).
gen ext-client "/DC=bar/DC=foo/CN=extuser"
gen ext-nobody "/DC=bar/DC=foo/CN=nobody"

rm -f ext-ca.key ext-ca.srl
