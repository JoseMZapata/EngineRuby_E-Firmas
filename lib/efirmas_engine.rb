require "efirmas_engine/version"
require "efirmas_engine/engine"

module EfirmasEngine
  mattr_accessor :user_class
  @@user_class = "User"

  def self.setup
    yield self
  end

  def self.user_class_name
    @@user_class.constantize
  end
end