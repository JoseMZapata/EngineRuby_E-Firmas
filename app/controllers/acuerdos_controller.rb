class AcuerdosController < ApplicationController

    def new
        @acuerdo = Acuerdo.new
    end

    def show
        @acuerdo = Acuerdo.find(params[:id])
    end
    def index
        @acuerdos = Acuerdo.all
    end

    def edit
        @acuerdo = Acuerdo.find(params[:id])
    end

    def create
        @acuerdo = Acuerdo.new(acuerdo_params.except(:user_ids, :file))
        @acuerdo.usuario_creador_id = 1

        begin
        ActiveRecord::Base.transaction do
            @acuerdo.save!

            archivo = params[:acuerdo][:file]
            raise "No se ha subido ningún archivo." unless archivo

            file_content = archivo.read
            file_hash = OpenSSL::Digest::SHA256.hexdigest(file_content)

            file_record = FileRecord.create!(
                nombre_archivo: archivo.original_filename,
                acuerdo_id: @acuerdo.id,
                tipo_archivo: archivo.content_type || 'application/octet-stream',
                byte_size: archivo.size,
                llave: file_hash
            )

            storage_path = Rails.root.join('storage', file_record.id.to_s)
            FileUtils.mkdir_p(storage_path)

            file_location = storage_path.join(archivo.original_filename)
            File.open(file_location, 'wb') do |file|
                file.write(file_content)
            end

            # Guardar usuarios relacionados (firmantes)
            user_ids = params.dig(:acuerdo, :user_ids)&.reject(&:blank?)
            if user_ids.present?
                user_ids.each do |user_id|
                    AcuerdoFirma.create!(
                    acuerdo_id: @acuerdo.id,
                    user_id: user_id,
                    firma_id: nil,
                    status: 'pendiente'
                    )
                end
            end

            # Redirigir según si el creador también firma
            if params[:acuerdo][:firmar_creador] == '1'
                redirect_to new_firma_path(acuerdo_id: @acuerdo.id) and return
            else
                redirect_to @acuerdo, notice: 'Acuerdo creado correctamente.' and return
            end
        end
        rescue => e
            flash.now[:alert] = "No se pudo crear el acuerdo: #{e.message}"
            @acuerdo ||= Acuerdo.new(acuerdo_params.except(:user_ids)) # <- Asegura que no sea nil
            render :new, status: :unprocessable_entity
        end
    end

    def archivo
        @acuerdo = Acuerdo.find(params[:id])
        file_record = @acuerdo.files.first

        if file_record
        # Construimos la ruta exacta al archivo en el storage
        file_path = Rails.root.join('storage', file_record.id.to_s, file_record.nombre_archivo)

        if File.exist?(file_path)
            # Verificamos si queremos descargar o mostrar
            disposicion = params[:disposition] == 'attachment' ? 'attachment' : 'inline'
            
            # Usamos send_data para enviar el archivo al navegador
            send_data(
            File.read(file_path),
            filename: file_record.nombre_archivo,
            type: file_record.tipo_archivo || 'application/pdf',
            disposition: disposicion # 'inline' le dice al navegador que lo muestre
            )
        else
            redirect_to @acuerdo, alert: "El archivo no fue encontrado en el servidor."
        end
        else
            redirect_to @acuerdo, alert: "El acuerdo no tiene un archivo asociado."
        end
    end

  private

  def acuerdo_params
    params.require(:acuerdo).permit(:name, user_ids: [])
  end
end
