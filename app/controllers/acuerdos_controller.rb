class AcuerdosController < ApplicationController

    def new
        @acuerdo = Acuerdo.new
    end

    def show
        @acuerdo = Acuerdo.find(params[:id])
    end


    def create
        @acuerdo = Acuerdo.new(acuerdo_params)
        @acuerdo.usuario_creador_id = 1 

        ActiveRecord::Base.transaction do
            @acuerdo.save!

            archivo = params[:acuerdo][:file]
            raise "No se ha subido ningún archivo." unless archivo

            storage_path = Rails.root.join('storage')
            FileUtils.mkdir_p(storage_path) 
            file_location = storage_path.join(archivo.original_filename)

            File.open(file_location, 'wb') do |file|
            file.write(archivo.read)
            end

            file_record = FileRecord.create!(
            nombre_archivo: archivo.original_filename,
            acuerdo_id: @acuerdo.id,
            tipo_archivo: archivo.content_type || 'application/octet-stream',
            byte_size: archivo.size,
            llave: SecureRandom.hex(8)
            )

            if params[:acuerdo][:firmar_creador] == '1'
                redirect_to new_firma_path(acuerdo_id: @acuerdo.id)
            else
                redirect_to @acuerdo, notice: 'Acuerdo creado correctamente.'
            end
        end
        rescue => e
    
            flash.now[:alert] = "No se pudo crear el acuerdo: #{e.message}"
            render :new, status: :unprocessable_entity
        end
end

    private

    def acuerdo_params
        params.require(:acuerdo).permit(:name)
    end
