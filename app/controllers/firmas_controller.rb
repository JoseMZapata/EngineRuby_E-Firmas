class FirmasController < ApplicationController
    def new 
        @firma = Firma.new
    end

    def create
        uploaded_document = params[:firma][:file] # Documento a firmar (flexible)
        uploaded_cert     = params[:firma][:public_key] # Archivo de Certificado (estricto)
        uploaded_key      = params[:firma][:private_key] # Archivo de Clave Privada (estricto)
       
        @firma = Firma.new(firma_params.except(:file, :public_key, :private_key))
        if uploaded_document.blank?
            @firma.errors.add(:file, "debe ser seleccionado (documento a firmar).")
            return render :new, status: :unprocessable_content
        end
        if uploaded_cert.present?
            filename = uploaded_cert.original_filename
            
            # 1. Validar extensión de Certificado
            unless filename.downcase.ends_with?('.pfx') || filename.downcase.ends_with?('.cer')
                @firma.errors.add(:public_key, "debe ser un certificado válido (.cer o .pfx).")
                return render :new, status: :unprocessable_content
            end

            # 2. Validar la vigencia del Certificado
            if check_certificate_vldty(uploaded_cert.tempfile.path)
                @firma.public_key = uploaded_cert.original_filename 
            else
                @firma.errors.add(:public_key, "El certificado no es válido o ha expirado.")
                return render :new, status: :unprocessable_content
            end
        end
        if uploaded_key.present?
            unless uploaded_key.original_filename.downcase.ends_with?('.key')
                @firma.errors.add(:private_key, "debe ser un archivo de clave privada (.key).")
                return render :new, status: :unprocessable_content
            end
            @firma.private_key = uploaded_key.original_filename 
        end
        

        @firma.file = uploaded_document.original_filename
        
        if @firma.save
            redirect_to @firma, notice: 'Firma y archivos validados.'
        else
            render :new, status: :unprocessable_content
        end
    end

    private

    

    def firma_params
        params.require(:firma).permit(:public_key, :private_key, :password, :file)
    end

    def check_certificate_vldty(cert_path)
        unless File.exist?(cert_path)
            Rails.logger.error("ERROR: El certificado '#{cert_path}' no existe.")
            return false
        end

        cert = OpenSSL::X509::Certificate.new(File.read(cert_path)) 
        not_before = cert.not_before
        not_after = cert.not_after
        current_time = Time.now


        if current_time >= not_before && current_time <= not_after
            Rails.logger.info("El certificado es válido y esta vigente.")
            return true
        else 
            Rails.logger.warn("El certificado ha expirado o aún no es válido.")
            return false
        end
    end

    def sign_with_efirma(doc_path, private_key_path, cert_path)
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

        signature = private_key.sign(OpenSSL::Digest::SHA256.new, OpenSSL::Digest::SHA256.digest(doc_data))

        # 5. convertimos a base64
        base64_signature = Base64.strict_encode64(signature)

        # 6. guardamos en un archivo
        output_path = "#{doc_path}.base64"
        File.open(output_path, 'w') { |f| f.write(base64_signature) }

        puts "Archivo firmado y codificado en Base64 creado: #{output_path}"
    end
end
