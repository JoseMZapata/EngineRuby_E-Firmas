#!/usr/bin/env bash
set -euo pipefail

# sign_doc.sh
# Uso:
#   ./sign_doc.sh --help
#
# Funciones:
#   - generate-test-cert : crea key.pem y cert.pem (self-signed) para pruebas
#   - sign-cms           : genera firma CMS/PKCS7 (attached or detached)
#   - verify-cms         : verifica firma CMS/PKCS7
#   - import-pkcs12      : extrae key/cert de un .p12 (pfx) — para e.firma reales

usage() {
  cat <<EOF
Uso:
  $0 generate-test-cert
  $0 sign-cms <file>     -> crea <file>.p7s (attached PEM by default)
  $0 verify-cms <file>   -> verifica <file>.p7s
  $0 import-pkcs12 <mypfx.p12> <outprefix>   -> extrae outprefix-key.pem outprefix-cert.pem
Notes:
  - Para usar un certificado real (.p12/.pfx) use import-pkcs12 y luego sign-raw / sign-cms con los archivos extraídos.
  - El script usa SHA256.
EOF
  exit 1
}

require_openssl() {
  if ! command -v openssl >/dev/null 2>&1; then
    echo "ERROR: openssl no encontrado. Instala openssl (libssl) y vuelve a intentar." >&2
    exit 2
  fi
  openssl version
}

generate_test_cert() {
  echo "Generando clave privada (key.pem) y certificado self-signed (cert.pem) de prueba..."
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out key.pem
  openssl req -new -x509 -sha256 -days 365 -key key.pem -out cert.pem -subj "/C=MX/ST=State/L=City/O=Test/CN=test.local"
  chmod 600 key.pem
  echo "Generado: key.pem, cert.pem"
}


sign_cms() {
  local file="$1"
  local cert="${2:-cert.pem}"
  local key="${3:-key.pem}"
  local out="${file}.p7s"

  if [ ! -f "$file" ]; then echo "ERROR: archivo '$file' no existe"; exit 3; fi
  if [ ! -f "$cert" ]; then echo "ERROR: certificado '$cert' no encontrado"; exit 3; fi
  if [ ! -f "$key" ]; then echo "ERROR: clave privada '$key' no encontrada"; exit 3; fi

  # Genera output en PEM (por defecto attached). Para detached pase -nodetach
  echo "Creando firma CMS/PKCS7 (attached) -> $out"
  openssl cms -sign -binary -in "$file" -signer "$cert" -inkey "$key" -outform PEM -out "$out" -nodetach -nosmimecap
  echo "Archivo firmado CMS creado: $out"
}

verify_cms() {
  local file="$1"
  local p7s="${file}.p7s"
  local ca="${2:-cert.pem}"   # para self-signed usamos cert.pem como CA

  if [ ! -f "$file" ]; then echo "ERROR: archivo '$file' no existe"; exit 3; fi
  if [ ! -f "$p7s" ]; then echo "ERROR: firma CMS '$p7s' no encontrada"; exit 3; fi
  if [ ! -f "$ca" ]; then echo "WARNING: CA ($ca) no encontrado; verificando sin CA (solo parseo)" ; fi

  echo "Verificando CMS..."
  # -verify validará la firma; para self-signed usamos -CAfile cert.pem
  if [ -f "$ca" ]; then
    openssl cms -verify -in "$p7s" -inform PEM -content "$file" -CAfile "$ca" -no_signer_cert_verify -no_attr_verify -out /dev/null
  else
    openssl cms -verify -in "$p7s" -inform PEM -content "$file" -no_signer_cert_verify -no_attr_verify -out /dev/null
  fi

  echo "Verificación CMS completada (si no hubo error, la firma es válida y el contenido coincide)."
}

import_pkcs12() {
  local p12="$1"
  local outprefix="${2:-efirma}"
  if [ ! -f "$p12" ]; then echo "ERROR: archivo p12/pfx '$p12' no existe"; exit 3; fi
  echo "Importando $p12 -> ${outprefix}-key.pem, ${outprefix}-cert.pem"
  # Extraer clave privada (se pedirá passphrase del .p12)
  openssl pkcs12 -in "$p12" -nocerts -nodes -out "${outprefix}-key.pem"
  # Extraer certificado
  openssl pkcs12 -in "$p12" -clcerts -nokeys -out "${outprefix}-cert.pem"
  chmod 600 "${outprefix}-key.pem"
  echo "Import completo."
}

# ---- main ----
if [ $# -lt 1 ]; then usage; fi
require_openssl

cmd="$1"; shift || true

case "$cmd" in
  generate-test-cert) generate_test_cert ;;
  sign-cms)
    [ $# -ge 1 ] || { echo "Falta archivo"; usage; }
    sign_cms "$1" "${2:-cert.pem}" "${3:-key.pem}"
    ;;
  verify-cms)
    [ $# -ge 1 ] || { echo "Falta archivo"; usage; }
    verify_cms "$1" "${2:-cert.pem}"
    ;;
  import-pkcs12)
    [ $# -ge 1 ] || { echo "Falta archivo .p12"; usage; }
    import_pkcs12 "$1" "${2:-efirma}"
    ;;
  *)
    usage
    ;;
esac
