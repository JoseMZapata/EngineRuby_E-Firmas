module EfirmasEngine
  class Acuerdo < ApplicationRecord
    self.table_name = 'efirmas_engine_acuerdos'
    
    belongs_to :creador, class_name: 'User', foreign_key: 'usuario_creador_id'
    has_many :acuerdo_firmas, class_name: 'EfirmasEngine::AcuerdoFirma', dependent: :destroy
    has_many :firmas, through: :acuerdo_firmas
    has_many :files, class_name: 'EfirmasEngine::FileRecord', foreign_key: 'acuerdo_id', dependent: :destroy
    belongs_to :usuario_creador, class_name: 'User', foreign_key: 'usuario_creador_id', optional: true
    has_many :comentario_acuerdos, class_name: 'EfirmasEngine::ComentarioAcuerdo', dependent: :destroy

    has_many :users, through: :acuerdo_firmas, source: :user
    
    def puede_firmar?(user)
      acuerdo_firmas.exists?(user_id: user.id, status: 'pendiente')
    end
  end
end