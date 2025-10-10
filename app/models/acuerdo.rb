class Acuerdo < ApplicationRecord
  belongs_to :creador, class_name: 'User', foreign_key: 'usuario_creador_id'
  has_many :acuerdo_firmas
  has_many :firmas, through: :acuerdo_firmas
  has_many :files
end
