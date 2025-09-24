require 'openssl'
require 'base64'


def check_certificate_vldty(cert_path)
  unless File.exist?(cert_path)
    puts "ERROR: El certificado '#{cert_path}' no existe."
    exit(1)
  end

  # Cargamos el certificado desde el archivo
  cert = OpenSSL::X509::Certificate.new(File.read(cert_path))  #Carga la información del certificado
  
  # Obtenemos las fechas de validez
  not_before = cert.not_before                                 #Obtiene los datos puestos de la información cargada
  not_after = cert.not_after                                   #Validity Not Before: Oct 13 20:09:11 2020 GMT
                                                               #         Not After : Oct 13 20:09:51 2024 GMT
  current_time = Time.now                                      #Toma la fecha actual

  # Verificamos si la fecha actual está dentro del rango de validez
  if current_time >= not_before && current_time <= not_after
    puts "El certificado es válido y está vigente."                         #Compara las fechas si es vigente
    return true
  else
    puts "El certificado ha expirado o aún no es válido."
    puts "  Periodo de validez: #{not_before.strftime('%Y-%m-%d')} a #{not_after.strftime('%Y-%m-%d')}"    #si no es vigente: 
    return false
  end
end

def sign_with_efirma(doc_path, private_key_path,cert_path)
  # 1. leemos y cargamos la clave privada
  unless File.exist?(private_key_path)
    puts "ERROR: La clave privada '#{private_key_path}' no existe."      #En caso de no encontrar el archivo
    exit(1)
  end
  private_key = OpenSSL::PKey::RSA.new(File.read(private_key_path))

  # 2. leemos el documento por firmar
  unless File.exist?(doc_path)
    puts "ERROR: El documento '#{doc_path}' no existe."    # En caso de no encontrar el documento
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