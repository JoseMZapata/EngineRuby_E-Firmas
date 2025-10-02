class Users
  attr_accessor :id, :name, :rfc

  USERS = [
    { id: 1, name: 'ISMAEL HERNANDEZ LANDEROS', rfc: 'HELI860902AQ1' },
    { id: 2, name: 'JOSE MANUEL ZAPATA RANGEL', rfc: 'ZARM040223C89' },
  ]

  def initialize(id:, name:, rfc:)
    @id = id
    @name = name
    @rfc = rfc
  end

  def to_h
    { id: @id, name: @name, rfc: @rfc }
  end

  def self.find_by_rfc(rfc)
    data = USERS.find { |u| u[:rfc] == rfc }
    data ? new(**data) : nil
  end

  def self.valid_rfc?(rfc)
    !!find_by_rfc(rfc)
  end
end
