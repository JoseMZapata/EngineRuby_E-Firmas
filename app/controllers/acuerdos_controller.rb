class AcuerdosController < ApplicationController

  def new
    @acuerdo = Acuerdo.new
  end

  def show
    @acuerdo = Acuerdo.find(params[:id])
    @comentarios = @acuerdo.comentario_acuerdos.includes(:user).recientes
    @comentario = ComentarioAcuerdo.new
  end
  def update
    @acuerdo = Acuerdo.find(params[:id])
    acuerdo_modificado = false

    begin
      ActiveRecord::Base.transaction do
        # Actualizar nombre si cambió
        if params[:acuerdo][:name].present? && params[:acuerdo][:name] != @acuerdo.name
          @acuerdo.update!(name: params[:acuerdo][:name])
          acuerdo_modificado = true
        end

        # Reemplazar archivo si se subió uno nuevo
        if params[:acuerdo][:file].present?
          # Eliminar archivo anterior
          old_file = @acuerdo.files.first
          if old_file
            old_file_path = Rails.root.join('storage', old_file.id.to_s)
            FileUtils.rm_rf(old_file_path) if File.exist?(old_file_path)
            old_file.destroy
          end

          # Guardar nuevo archivo
          archivo = params[:acuerdo][:file]
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

          acuerdo_modificado = true
        end

        # Actualizar firmantes si cambiaron
        if params[:acuerdo][:user_ids].present?
          new_user_ids = params[:acuerdo][:user_ids].reject(&:blank?).map(&:to_i)
          current_user_ids = @acuerdo.acuerdo_firmas.pluck(:user_id)

          if new_user_ids.sort != current_user_ids.sort
            # Eliminar firmantes que ya no están
            @acuerdo.acuerdo_firmas.where.not(user_id: new_user_ids).destroy_all

            # Agregar nuevos firmantes
            new_user_ids.each do |user_id|
              unless @acuerdo.acuerdo_firmas.exists?(user_id: user_id)
                AcuerdoFirma.create!(
                  acuerdo_id: @acuerdo.id,
                  user_id: user_id,
                  status: 'pendiente'
                )
              end
            end

            acuerdo_modificado = true
          end
        end

        # Si hubo modificaciones, resetear todas las firmas y notificar
        if acuerdo_modificado
          # Resetear status de todas las firmas a pendiente
          @acuerdo.acuerdo_firmas.update_all(status: 'pendiente', firma_id: nil)

          # Notificar a todos los firmantes
          @acuerdo.acuerdo_firmas.each do |acuerdo_firma|
            user = acuerdo_firma.user
            InvitacionFirmaMailer.notificar_modificacion(user, @acuerdo).deliver_later
          end
        end

        redirect_to @acuerdo, notice: 'Acuerdo actualizado exitosamente. Se ha notificado a los firmantes.'
      end
    rescue => e
      flash.now[:alert] = "Error al actualizar el acuerdo: #{e.message}"
      render :edit, status: :unprocessable_entity
    end
  end

  def index
    @acuerdos = Acuerdo.all
  end

  def edit
    @acuerdo = Acuerdo.find(params[:id])
  end

  def create
    @acuerdo = Acuerdo.new(acuerdo_params.except(:user_ids, :file, :firmar_creador))
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

            # Enviar correo de notificación a cada firmante
            user = User.find(user_id)
            InvitacionFirmaMailer.notificar_firmante(user, @acuerdo).deliver_later
          end
        end

        # Redirigir según si el creador también firma
        if params[:acuerdo][:firmar_creador] == '1'
          redirect_to new_firma_path(acuerdo_id: @acuerdo.id) and return
        else
          redirect_to @acuerdo, notice: 'Acuerdo creado y notificaciones enviadas correctamente.' and return
        end
      end
    rescue => e
      flash.now[:alert] = "No se pudo crear el acuerdo: #{e.message}"
      @acuerdo ||= Acuerdo.new(acuerdo_params.except(:user_ids))
      render :new, status: :unprocessable_entity
    end
  end

  def archivo
    @acuerdo = Acuerdo.find(params[:id])
    file_record = @acuerdo.files.first

    if file_record
      file_path = Rails.root.join('storage', file_record.id.to_s, file_record.nombre_archivo)

      if File.exist?(file_path)
        disposition = params[:disposition] == 'attachment' ? 'attachment' : 'inline'
        send_data(
          File.read(file_path),
          filename: file_record.nombre_archivo,
          type: file_record.tipo_archivo || 'application/pdf',
          disposition: disposition
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
    params.require(:acuerdo).permit(:name, :file, :firmar_creador, user_ids: [])
  end
end
