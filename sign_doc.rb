require 'openssl'

def generate_test_cert()
  key = OpenSSL::PKey::RSA.new(2048)
  name = OpenSSL::X509::Name.parse('CN=Test,O=MyOrg,C=US')
  cert = OpenSSL::X509::Certificate.new
  cert.version = 2
  cert.serial = 1
  cert.subject = name
  cert.issuer = name
  cert.public_key = key.public_key
  cert.not_before = Time.now
  cert.not_after = cert.not_before + 365 * 24 * 60 * 60 # Válido por un año

  efirma_key_path = 'key.pem'
  efirma_cert_path = 'cert.pem'

  File.open(efirma_key_path, 'w') { |f| f.write(key.to_pem) }
  File.open(efirma_cert_path, 'w') { |f| f.write(cert.to_pem) }

  puts "Certificado de prueba generado:"
  puts " - Llave privada: #{efirma_key_path}"
  puts " - Certificado: #{efirma_cert_path}"
end


def sign_cms()
  input_path, cert_path, key_path = ARGV[0], ARGV[1], ARGV[2]

  unless File.exist?(input_path)
    puts "ERROR: El archivo de entrada '#{input_path}' no existe."
    exit(1)
  end
  unless File.exist?(cert_path)
    puts "ERROR: El certificado '#{cert_path}' no existe."
    exit(2)
  end
  unless File.exist?(key_path)
    puts "ERROR: La llave privada '#{key_path}' no existe."
    exit(3)
  end

  # Leemos el contenido del archivo a firmar
  data = File.read(input_path, binmode: true)

  # Cargamos el certificado y la llave privada
  cert = OpenSSL::X509::Certificate.new(File.read(cert_path, binmode: true))
  key = OpenSSL::PKey::RSA.new(File.read(key_path, binmode: true))

  # Creamos el objeto CMS
  cms = OpenSSL::CMS.sign(cert, key, data, [], OpenSSL::CMS_DETACHED)

  # Escribimos la firma CMS en un archivo .p7s
  output_path = "#{input_path}.p7s"
  File.open(output_path, 'wb') { |f| f.write(cms.to_der) }

  puts "Archivo firmado creado: #{output_path}"
end

def verify_cms()
  input_path, cert_path = ARGV[0], ARGV[1]

  unless File.exist?(input_path)
    puts "ERROR: El archivo firmado '#{input_path}' no existe."
    exit(1)
  end
  unless File.exist?(cert_path)
    puts "ERROR: El certificado '#{cert_path}' no existe."
    exit(2)
  end

  # Leemos el contenido del archivo firmado
  cms_data = File.read(input_path, binmode: true)

  # Cargamos el certificado
  cert = OpenSSL::X509::Certificate.new(File.read(cert_path, binmode: true))

  # Verificamos la firma CMS
  cms = OpenSSL::CMS.new(cms_data)
  begin
    cms.verify([cert], nil, nil, OpenSSL::CMS_DETACHED)
    puts "La firma es válida."
  rescue OpenSSL::CMS::VerificationError => e
    puts "La firma no es válida: #{e.message}"
    exit(3)
  end
end


def import_pkcs12(p12_path, password, out_prefix)
  unless File.exist?(p12_path)
    puts "ERROR: El archivo .p12 '#{p12_path}' no existe."
    exit(3)
  end

  puts "Importando #{p12_path} -> #{out_prefix}-key.pem, #{out_prefix}-cert.pem"

  # Lee el archivo P12 y extrae el par de llave/certificado
  pkcs12 = OpenSSL::PKCS12.new(File.read(p12_path, binmode: true), password)

  # Escribe la llave privada en un archivo PEM
  File.open("#{out_prefix}-key.pem", 'w') do |f|
    f.write(pkcs12.key.to_pem)
  end
  # Escribe el certificado en un archivo PEM
  File.open("#{out_prefix}-cert.pem", 'w') do |f|
    f.write(pkcs12.certificate.to_pem)
  end

  puts "Importación completa."
end

