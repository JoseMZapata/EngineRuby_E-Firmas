class InvitacionFirmaMailer < ApplicationMailer
  def notificar_firmante(user, acuerdo)
    @user = user
    @acuerdo = acuerdo
    @url_para_firmar = new_firma_url(acuerdo_id: @acuerdo.id) # URL para firmar

    mail(to: @user.email, subject: "Invitación para firmar el acuerdo: #{@acuerdo.name}")
  end
end