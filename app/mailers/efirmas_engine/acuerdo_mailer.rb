module EfirmasEngine
    class AcuerdoMailer < ApplicationMailer
        def notificar_problema(acuerdo, comentario)
            @acuerdo = acuerdo
            @comentario = comentario
            @creador = acuerdo.usuario
            @url_acuerdo = edit_acuerdo_url(@acuerdo)
            
            mail(
            to: @creador.email,
            subject: "Problema reportado en el acuerdo: #{@acuerdo.nombre}"
            )
        end
        
        def notificar_modificacion(acuerdo_firma)
            @acuerdo_firma = acuerdo_firma
            @acuerdo = acuerdo_firma.acuerdo
            @firmante = acuerdo_firma.usuario
            @url_firmar = firmar_acuerdo_url(@acuerdo)
            
            mail(
            to: @firmante.email,
            subject: "El acuerdo '#{@acuerdo.nombre}' ha sido modificado"
            )
        end
    end
end