module EfirmasEngine
  class ComentarioAcuerdo < ApplicationRecord
    self.table_name = 'efirmas_engine_comentario_acuerdos'
    
    belongs_to :acuerdo, class_name: 'EfirmasEngine::Acuerdo'
    belongs_to :user, foreign_key: 'usuario_id', class_name: 'User'
    
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
end
