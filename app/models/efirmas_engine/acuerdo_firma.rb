module EfirmasEngine
  class AcuerdoFirma < ApplicationRecord
    self.table_name = 'efirmas_engine_acuerdo_firmas'
    
    belongs_to :acuerdo, class_name: 'EfirmasEngine::Acuerdo'
    belongs_to :user, class_name: 'User'
    belongs_to :firma, class_name: 'EfirmasEngine::Firma', optional: true
  end
end