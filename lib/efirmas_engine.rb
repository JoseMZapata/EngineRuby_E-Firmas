require "efirmas_engine/version"
require "efirmas_engine/engine"

module EfirmasEngine
  mattr_accessor :user_class
  @@user_class = "User"

  mattr_accessor :current_user_method
  @@current_user_method = :current_user

  def self.setup
    yield self
  end

  def self.user_class_name
    @@user_class.constantize
  end
  
  def self.user_model
    user_class_name
  end
end