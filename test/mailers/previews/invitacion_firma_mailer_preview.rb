# Preview all emails at http://localhost:3000/rails/mailers/invitacion_firma_mailer
class InvitacionFirmaMailerPreview < ActionMailer::Preview
  # Preview this email at http://localhost:3000/rails/mailers/invitacion_firma_mailer/notificar_firmante
  def notificar_firmante
    InvitacionFirmaMailer.notificar_firmante
  end
end
