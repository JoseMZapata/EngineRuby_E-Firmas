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
    if @acuerdo.save
      archivo = params[:acuerdo][:file]
      file_record = FileRecord.new(
        nombre_archivo: archivo.original_filename,
        acuerdo_id: @acuerdo.id,
        tipo_archivo: archivo.content_type || 'application/octet-stream',
        byte_size: archivo.size,
        llave: SecureRandom.hex(8)
      )
      unless file_record.save
        @acuerdo.destroy
        flash.now[:alert] = "No se pudo guardar el archivo: #{file_record.errors.full_messages.join(', ')}"
        render :new, status: :unprocessable_content and return
      end
      if params[:acuerdo][:firmar_creador] == '1'
        redirect_to new_firma_path(acuerdo_id: @acuerdo.id)
      else
        redirect_to @acuerdo, notice: 'Acuerdo creado correctamente.'
      end
    else
      render :new, status: :unprocessable_content
    end
  end

  private

  def acuerdo_params
    params.require(:acuerdo).permit(:name)
  end
end
