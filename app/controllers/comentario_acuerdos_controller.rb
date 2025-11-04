class ComentarioAcuerdosController < ApplicationController
  before_action :set_acuerdo
  
  def create
    @comentario = @acuerdo.comentario_acuerdos.build(comentario_params)

    @comentario.user_id = params[:user_id] 
    
    if @comentario.save
      InvitacionFirmaMailer.notificar_problema(@acuerdo, @comentario).deliver_later
      
      redirect_to @acuerdo, notice: "Tu comentario ha sido registrado y se notificó al creador del acuerdo"
    else
      flash[:alert] = "Hubo un error al guardar tu comentario: #{@comentario.errors.full_messages.join(', ')}"
      redirect_to @acuerdo
    end
  end
  
  private
  
  def set_acuerdo
    @acuerdo = Acuerdo.find(params[:acuerdo_id])
  end
  
  def comentario_params
    params.require(:comentario_acuerdo).permit(:motivo, :comentario)
  end
end