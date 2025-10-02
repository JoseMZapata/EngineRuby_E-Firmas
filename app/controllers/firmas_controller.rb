class FirmasController < ApplicationController
    def new 
        @firma = Firma.new
    end

    def create
        @firma = Firma.new(firma_params.except(:file, :public_key, :private_key))
        validate_firma_fields
        if @firma.valid?
            begin
                uploaded_document = params[:firma][:file]
                uploaded_key = params[:firma][:private_key]
                uploaded_cert = params[:firma][:public_key]
                if uploaded_document.present? && uploaded_key.present? && uploaded_cert.present?
                    doc_path = uploaded_document.tempfile.path
                    key_path = uploaded_key.tempfile.path
                    cert_path = uploaded_cert.tempfile.path
                    password = params[:firma][:password]
                    @firma.firma_base64 = sign_with_efirma(doc_path, key_path, cert_path, password)

                    cert = OpenSSL::X509::Certificate.new(File.read(cert_path))
                    cert_subject = cert.subject.to_a
                    rfc_from_cert = cert_subject.find { |name, _, _| name == 'serialNumber' }&.[](1)
                    user = Users.find_by_rfc(rfc_from_cert)
                    user1 = Users.find_by_rfc(Users::USERS.find { |u| u[:id] == 1 }[:curp])

                    if user.nil? || user.id != 1
                        @firma.errors.add(:personas_id, "El RFC del certificado no corresponde al usuario autenticado.")
                        return render :new, status: :unprocessable_content
                    end
                    @firma.personas_id = user.id

                    @firma.serie_certificado = cert.serial.to_s(16).upcase
                end
            rescue => e
                @firma.errors.add(:firma_base64, "No se pudo generar la firma: #{e.message}")
                return render :new, status: :unprocessable_content
            end
            @firma.save
            redirect_to @firma, notice: 'Firma y archivos validados.'
        else
            render :new, status: :unprocessable_content
        end
    end
    def validate_firma_fields
        uploaded_document = params[:firma][:file]
        uploaded_cert     = params[:firma][:public_key]
        uploaded_key      = params[:firma][:private_key]

        if uploaded_document.blank?
            @firma.errors.add(:file, "debe ser seleccionado (documento a firmar).")
        else
            @firma.file = uploaded_document.original_filename
        end

        if uploaded_cert.present?
            filename = uploaded_cert.original_filename
            unless filename.downcase.ends_with?('.pfx') || filename.downcase.ends_with?('.cer')
                @firma.errors.add(:public_key, "debe ser un certificado válido (.cer o .pfx).")
            end
            @firma.public_key = uploaded_cert.original_filename
            #if check_certificate_vldty(uploaded_cert.tempfile.path)
            #    @firma.public_key = uploaded_cert.original_filename 
            #else
             #   @firma.errors.add(:public_key, "El certificado no es válido o ha expirado.")
            #    return render :new, status: :unprocessable_content
            #end
        end

        if uploaded_key.present?
            unless uploaded_key.original_filename.downcase.ends_with?('.key')
                @firma.errors.add(:private_key, "debe ser un archivo de clave privada (.key).")
            end
            @firma.private_key = uploaded_key.original_filename
        end
    end

    private

    

    def firma_params
        params.require(:firma).permit(:public_key, :private_key, :password, :file)
    end
    # def check_certificate_vldty(cert_path)
    #     unless File.exist?(cert_path)
    #         Rails.logger.error("ERROR: El certificado '#{cert_path}' no existe.")
    #         return false
    #     end

    #     cert = OpenSSL::X509::Certificate.new(File.read(cert_path)) 
    #     not_before = cert.not_before
    #     not_after = cert.not_after
    #     current_time = Time.now


    #     if current_time >= not_before && current_time <= not_after
    #         Rails.logger.info("El certificado es válido y esta vigente.")
    #         return true
    #     else 
    #         Rails.logger.warn("El certificado ha expirado o aún no es válido.")
    #         return false
    #     end
    # end

    def sign_with_efirma(doc_path, private_key_path, cert_path, password = nil)
        unless File.exist?(private_key_path)
            raise "ERROR: La clave privada '#{private_key_path}' no existe."
        end
        key_data = File.read(private_key_path)
        begin
            private_key = password.present? ? OpenSSL::PKey::RSA.new(key_data, password) : OpenSSL::PKey::RSA.new(key_data)
        rescue OpenSSL::PKey::RSAError => e
            raise "No se pudo abrir la clave privada. ¿La contraseña es correcta?"
        end

        unless File.exist?(doc_path)
            raise "ERROR: El documento '#{doc_path}' no existe."
        end
        doc_data = File.read(doc_path)

        sha256_hash = OpenSSL::Digest::SHA256.digest(doc_data)
        signature = private_key.sign(OpenSSL::Digest::SHA256.new, sha256_hash)
        base64_signature = Base64.strict_encode64(signature)
        base64_signature
    end
end
