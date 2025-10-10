class FirmasController < ApplicationController

    def new
        @firma = Firma.new
    end

    def create
        @firma = Firma.new(firma_params.except(:public_key, :private_key))

        @firma.public_key = params[:firma][:public_key]&.original_filename
        @firma.private_key = params[:firma][:private_key]&.original_filename

        begin
            process_signature_and_assign_fields
        rescue => e
            @firma.errors.add(:firma_base64, "No se pudo generar la firma: #{e.message}")
            return render :new, status: :unprocessable_content
        end

        puts "DEBUG: user_id=#{@firma.user_id}, file_id=#{@firma.file_id}"
        if @firma.valid? && @firma.save
            redirect_to @firma, notice: 'Firma y archivos validados.'
        else
            puts "DEBUG: Firma not valid: #{@firma.errors.full_messages.inspect}"
            render :new, status: :unprocessable_content
        end
    end

    private


    def process_signature_and_assign_fields
        uploaded_document = params[:firma][:file]
        uploaded_key = params[:firma][:private_key]
        uploaded_cert = params[:firma][:public_key]
        password = params[:firma][:password]

        doc_path = uploaded_document.tempfile.path
        key_path = uploaded_key.tempfile.path
        cert_path = uploaded_cert.tempfile.path

        @firma.firma_base64 = sign_with_efirma(doc_path, key_path, cert_path, password)

        cert = OpenSSL::X509::Certificate.new(File.read(cert_path))
        rfc_from_cert = cert.subject.to_a.find { |name, _, _| name == 'serialNumber' }&.[](1)
        user = User.find_by_rfc(rfc_from_cert)

        if user.nil? || user.id != 1
            @firma.errors.add(:user_id, "El RFC del certificado no corresponde al usuario autenticado.")
            raise "RFC mismatch"
        end


        @firma.user_id = user.id

        acuerdo = Acuerdo.create!(name: "Acuerdo generado para archivo #{uploaded_document.original_filename}", usuario_creador_id: user.id)
        file_record = FileRecord.new(
            nombre_archivo: uploaded_document.original_filename,
            acuerdo_id: acuerdo.id,
            tipo_archivo: uploaded_document.content_type || 'application/octet-stream',
            byte_size: uploaded_document.size,
            llave: SecureRandom.hex(8)
        )
        unless file_record.save
            @firma.errors.add(:file_id, "No se pudo crear el archivo: #{file_record.errors.full_messages.join(', ')}")
            raise "FileRecord creation failed"
        end
        @firma.file_id = file_record.id

        hex_serial = cert.serial.to_s(16).upcase
        puts hex_serial
        text_serial = [hex_serial].pack("H*")
        puts text_serial
        @firma.serie_certificado = text_serial
    end


    def firma_params
        params.require(:firma).permit(:public_key, :private_key, :password)
    end

    def sign_with_efirma(doc_path, private_key_path, cert_path, password = nil)
        raise "ERROR: La clave privada '#{private_key_path}' no existe." unless File.exist?(private_key_path)
        key_data = File.read(private_key_path)
        private_key = begin
            password.present? ? OpenSSL::PKey::RSA.new(key_data, password) : OpenSSL::PKey::RSA.new(key_data)
        rescue OpenSSL::PKey::RSAError
            raise "No se pudo abrir la clave privada. ¿La contraseña es correcta?"
        end

        raise "ERROR: El documento '#{doc_path}' no existe." unless File.exist?(doc_path)
        doc_data = File.read(doc_path)

        sha256_hash = OpenSSL::Digest::SHA256.digest(doc_data)
        signature = private_key.sign(OpenSSL::Digest::SHA256.new, sha256_hash)
        Base64.strict_encode64(signature)
    end
end
