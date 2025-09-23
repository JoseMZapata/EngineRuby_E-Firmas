require 'openssl'
require 'base64'

def sign_with_efirma(doc_path, private_key_path)
  # 1. leemos y cargamos la clave privada
  unless File.exist?(private_key_path)
    puts "ERROR: La clave privada '#{private_key_path}' no existe."
    exit(1)
  end
  private_key = OpenSSL::PKey::RSA.new(File.read(private_key_path))

  # 2. leemos el documento por firmar
  unless File.exist?(doc_path)
    puts "ERROR: El documento '#{doc_path}' no existe."
    exit(1)
  end
  doc_data = File.read(doc_path)

  # 3. Hasheamos el documento con sha 256
  sha256_hash = OpenSSL::Digest::SHA256.digest(doc_data)

  # 4. firmamos el documento hasheado con la clave privada
  signature = private_key.sign(OpenSSL::Digest::SHA256.new, sha256_hash)

  # 5. convertimos a base64
  base64_signature = Base64.strict_encode64(signature)

  # 6. guardamos en un archivo
  output_path = "#{doc_path}.base64"
  File.open(output_path, 'w') { |f| f.write(base64_signature) }

  puts "Archivo firmado y codificado en Base64 creado: #{output_path}"
end