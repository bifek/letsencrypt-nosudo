#!/usr/bin/env bash
#
# LEDIR contains following dirs and files:
#   certs/ dir for successfully created csr, key and crt files
#   certs-test/ dir used when testing
#   user.pub  user account public key
#   user.key  optional user account private key for automatic signing
: ${LEDIR:=~/letsencrypt}
# "default" means webmaster@[shortest domain name of provided]
: ${EMAIL:=default}
: ${ACCOUNT_PUB:=$LEDIR/user.pub}
# if unset or non-existent you will get prompted to run openssl commands
: ${ACCOUNT_KEY:=$LEDIR/user.key}
: ${CERTSDIR:=$LEDIR/certs${TESTING:+-test}}
# optional WEBROOTS is dir that contains per-domain symlinks to their vhosts DocRoots.
# the idea is that sign_csr will write challenge data to $WEBROOTS/$DOMAIN/challenge-uri
# for LE to automatically verify the request (setting symlinks and permissions is up to you)
: ${WEBROOTS:=$LEDIR/webroots}

usage() {
  cat << EOF
  Usage:
   create_certs.sh main.domain [some extra domains...]

   TESTING=1 create_certs.sh some.testing
   create_certs.sh domain.name
   create_certs.sh domain.name another.domain.name and.another.one

EOF
  exit 0
}

custom_ssl_config() {
  cat /etc/ssl/openssl.cnf 
  printf "[letsencryptSAN]\n"
  printf "subjectAltName=DNS:%s" $1
  shift
  for dom; do
    printf ",DNS:%s" $dom
  done
}

gencsr() {  # list of domains
  local base=$TMP/$1
  openssl genrsa 4096 > "$base.key" 2>/dev/null
  openssl req -new -sha256 -key "$base.key" -subj "/" \
    -reqexts letsencryptSAN \
    -config <(custom_ssl_config "$@") > "$base.csr"
}

sign() {  # csr name
  local csr="$1"
  python sign_csr.py --email "$EMAIL" \
    --public-key "$ACCOUNT_PUB" \
    ${ACCOUNT_KEY:+--private-key "$ACCOUNT_KEY"} \
    ${WEBROOTS:+--webroots "$WEBROOTS"} \
    ${TESTING:+--testing} \
    "$csr" > "${csr%.csr}.crt"
}

info() {  # cert file
  openssl x509 -in "$1" -noout -text -certopt no_pubkey,no_sigdump,no_aux,no_version
}

main() {
  set -e  # exit if anything below fails
  [ -z "$1" ] && usage
  [ -f "$ACCOUNT_KEY" ] || unset ACCOUNT_KEY
  [ -d "$WEBROOTS" ] || unset WEBROOTS
  TMP=$(mktemp -d)
  trap "rm -rf '$TMP'" EXIT
  mkdir -p "$CERTSDIR/"

  gencsr "$@"
  sign "$TMP/$1.csr"
  mv -f "$TMP/$1".* "$CERTSDIR/"
  info "$CERTSDIR/$1.crt"
}

main "$@"
