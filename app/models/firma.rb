class Firma < ApplicationRecord
	attr_accessor :public_key, :private_key, :password, :file


	validates :public_key, presence: { message: "debe ser proporcionada." }
	validates :private_key, presence: { message: "debe ser proporcionada." }
	validates :password, presence: { message: "debe ser proporcionada." }
	validates :file, presence: { message: "debe ser proporcionado." }

	private


end
