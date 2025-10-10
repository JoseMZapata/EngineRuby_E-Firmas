class User < ApplicationRecord
  validates :name, presence: true
  validates :curp, presence: true, uniqueness: true

  # Returns the user as a hash (for compatibility)
  def to_h
    { id: id, name: name, curp: curp }
  end

  # Find user by curp (RFC)
  def self.find_by_rfc(curp)
    find_by(curp: curp)
  end

  # Validate if RFC exists
  def self.valid_rfc?(curp)
    exists?(curp: curp)
  end
end
