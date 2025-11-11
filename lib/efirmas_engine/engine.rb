module EfirmasEngine
  class Engine < ::Rails::Engine
    isolate_namespace EfirmasEngine

    config.generators do |g|
      g.test_framework :test_unit
      g.fixture_replacement :factory_bot
      g.factory_bot dir: 'spec/factories'
    end

    config.to_prepare do
      ApplicationController.helper(Rails.application.helpers)
    end
  end
end
