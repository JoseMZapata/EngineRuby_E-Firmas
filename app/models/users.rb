class Users
  attr_accessor :id, :name, :curp

  USERS = [
    { id: 1, name: 'ISMAEL HERNANDEZ LANDEROS', curp: 'HELI860902HDGRNS01' },
    { id: 2, name: 'JOSE MANUEL ZAPATA RANGEL', curp: 'ZARM040223HDGPNNA9' },
  ]

  def initialize(id:, name:, curp:)
    @id = id
    @name = name
    @curp = curp
  end

  def to_h
    { id: @id, name: @name, curp: @curp }
  end

  def self.find_by_rfc(curp)
    data = USERS.find { |u| u[:curp] == curp }
    data ? new(**data) : nil
  end

  def self.valid_rfc?(curp)
    !!find_by_curp(curp)
  end
end
