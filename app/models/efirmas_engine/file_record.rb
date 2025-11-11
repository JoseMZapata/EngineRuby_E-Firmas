module EfirmasEngine
  class FileRecord < ApplicationRecord
    self.table_name = 'efirmas_engine_files'
    
    belongs_to :acuerdo, class_name: 'EfirmasEngine::Acuerdo'
    has_many :firmas, class_name: 'EfirmasEngine::Firma', foreign_key: 'file_id'
  end
end