module EfirmasEngine
    class InvitacionFirmaMailer < ApplicationMailer
        def notificar_firmante(user, acuerdo)
            @user = user
            @acuerdo = acuerdo
            @url_para_firmar = new_firma_url(acuerdo_id: @acuerdo.id)

            mail(to: @user.email, subject: "Invitación para firmar el acuerdo: #{@acuerdo.name}")
        end
        
        def notificar_problema(acuerdo, comentario)
            @acuerdo = acuerdo
            @comentario = comentario
            @creador = acuerdo.usuario_creador
            @url_acuerdo = edit_acuerdo_url(@acuerdo)
            
            mail(
            to: @creador.email,
            subject: "Problema reportado en el acuerdo: #{@acuerdo.name}"
            )
        end
        
        def notificar_modificacion(user, acuerdo)
            @user = user
            @acuerdo = acuerdo
            @url_para_firmar = new_firma_url(acuerdo_id: @acuerdo.id)
            
            mail(
            to: @user.email,
            subject: "El acuerdo '#{@acuerdo.name}' ha sido modificado"
            )
        end
    end
end