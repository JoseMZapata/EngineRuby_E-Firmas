class FirmasController < ApplicationController

    def new
        @firma = Firma.new
        prepare_form_variables(params[:acuerdo_id])
    end

    def create
        acuerdo_id = params.dig(:firma, :acuerdo_id)
        acuerdo = Acuerdo.find(acuerdo_id)
        file_record = acuerdo.files.first

        @firma = Firma.new(firma_params)
        @firma.public_key = params[:firma][:public_key]&.original_filename
        @firma.private_key = params[:firma][:private_key]&.original_filename
        unless file_record
            prepare_form_variables(acuerdo.id)
            @firma.errors.add(:base, "El acuerdo no tiene archivo asociado.")
            return render :new, status: :unprocessable_content
        end

        process_signature_and_assign_fields_firma(file_record, acuerdo)

        if @firma.valid? && @firma.save
            acuerdo_firma_pendiente = AcuerdoFirma.find_by(
                acuerdo_id: acuerdo.id,
                user_id: @firma.user_id,
                status: 'pendiente'
                )

                if acuerdo_firma_pendiente
                    acuerdo_firma_pendiente.update!(firma_id: @firma.id, status: 'completada')
                else
                    AcuerdoFirma.create!(acuerdo_id: acuerdo.id, user_id: @firma.user_id, firma_id: @firma.id, status: 'completada')
                end                
                redirect_to acuerdo, notice: 'Firma creada y asociada al acuerdo exitosamente.'
            else
                prepare_form_variables(acuerdo.id)
                render :new, status: :unprocessable_entity
            end
        end
        rescue => e
            prepare_form_variables(params[:firma][:acuerdo_id])
            flash.now[:alert] = "Error al procesar la firma: #{e.message}"
            render :new, status: :unprocessable_entity
  
    end

    

    private

    def prepare_form_variables(selected_acuerdo_id = nil)
        @acuerdos = Acuerdo.all
        if selected_acuerdo_id
            @selected_acuerdo = Acuerdo.find_by(id: selected_acuerdo_id)
        end
    end
    def process_signature_and_assign_fields_firma(file_record, acuerdo)
        uploaded_key = params[:firma][:private_key]
        uploaded_cert = params[:firma][:public_key]
        password = params[:firma][:password]

        doc_path = file_record.nombre_archivo.present? ? file_record_path(file_record) : nil
        key_path = uploaded_key.tempfile.path
        cert_path = uploaded_cert.tempfile.path

        raise "No se encontró el archivo del acuerdo" unless doc_path && File.exist?(doc_path)

        @firma.firma_base64 = sign_with_efirma(doc_path, key_path, cert_path, password)

        cert = OpenSSL::X509::Certificate.new(File.read(cert_path))
        rfc_from_cert = cert.subject.to_a.find { |name, _, _| name == 'serialNumber' }&.[](1)
        user = User.find_by_rfc(rfc_from_cert)

        if user.nil?
            @firma.errors.add(:user_id, "El RFC del certificado no corresponde a ningún usuario registrado.")
            raise "RFC mismatch"
        end

        @firma.user_id = user.id
        @firma.file_id = file_record.id

        hex_serial = cert.serial.to_s(16).upcase
        text_serial = [hex_serial].pack("H*")
        @firma.serie_certificado = text_serial
    end

    def file_record_path(file_record)
        Rails.root.join('storage', file_record.id.to_s,file_record.nombre_archivo)
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
