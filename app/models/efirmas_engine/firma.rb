module EfirmasEngine
  class Firma < ApplicationRecord
    self.table_name = 'efirmas_engine_firmas'
    
    attr_accessor :public_key, :private_key, :password

    belongs_to :user, class_name: 'User'
    belongs_to :file_record, class_name: 'EfirmasEngine::FileRecord', foreign_key: 'file_id'
    has_many :acuerdo_firmas, class_name: 'EfirmasEngine::AcuerdoFirma'
    has_many :acuerdos, through: :acuerdo_firmas

    validates :public_key, presence: { message: "debe ser proporcionada." }
    validates :private_key, presence: { message: "debe ser proporcionada." }
    validates :password, presence: { message: "debe ser proporcionada." }
  end
end