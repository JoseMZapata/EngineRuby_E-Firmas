class ComentarioAcuerdo < ApplicationRecord
    belongs_to :acuerdo
    belongs_to :user
    
    MOTIVOS = [
        "No tengo efirma",
        "Tengo dudas sobre el contenido del documento",
        "Hay un error en el documento",
        "No soy uno de los firmantes",
        "Hay un error en el RFC firmado"
    ].freeze
    
    validates :motivo, inclusion: { in: MOTIVOS }
    validates :comentario, presence: true
    
    scope :recientes, -> { order(created_at: :desc) }


end
