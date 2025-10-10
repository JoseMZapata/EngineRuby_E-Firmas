class Firma < ApplicationRecord
	attr_accessor :public_key, :private_key, :password

	belongs_to :user
	belongs_to :file_record, class_name: 'FileRecord', foreign_key: 'file_id'
	has_many :acuerdo_firmas

	validates :public_key, presence: { message: "debe ser proporcionada." }
	validates :private_key, presence: { message: "debe ser proporcionada." }
	validates :password, presence: { message: "debe ser proporcionada." }
end
