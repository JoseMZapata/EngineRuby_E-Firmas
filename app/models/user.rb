class User < ApplicationRecord
  validates :name, presence: true
  validates :curp, presence: true, uniqueness: true
  validates :email, presence: true, uniqueness: true
  validates :email, format: { with: URI::MailTo::EMAIL_REGEXP, message: "debe ser un formato de email válido" }
  
  has_many :acuerdo_firmas
  has_many :acuerdos, through: :acuerdo_firmas
  def to_h
    { id: id, name: name, curp: curp }
  end

  def self.find_by_rfc(curp)
    find_by(curp: curp)
  end

  def self.valid_rfc?(curp)
    exists?(curp: curp)
  end
end
