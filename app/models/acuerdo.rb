class Acuerdo < ApplicationRecord
  belongs_to :creador, class_name: 'User', foreign_key: 'usuario_creador_id'
  has_many :comentario_acuerdos, dependent: :destroy
  has_many :acuerdo_firmas, dependent: :destroy
  has_many :firmas, through: :acuerdo_firmas
  has_many :files, class_name: 'FileRecord', dependent: :destroy
  belongs_to :usuario_creador, class_name: 'User', foreign_key: 'usuario_creador_id', optional: true


  has_many :users, through: :acuerdo_firmas

  def puede_firmar?(user)
    acuerdo_firmas.exists?(user_id: user.id, status: 'pendiente')
  end

end
