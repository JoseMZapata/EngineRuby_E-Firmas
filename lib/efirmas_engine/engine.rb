module EfirmasEngine
  class Engine < ::Rails::Engine
    isolate_namespace EfirmasEngine

    config.generators do |g|
      g.test_framework :test_unit
      g.fixture_replacement :factory_bot
      g.factory_bot dir: 'spec/factories'
    end

    initializer "efirmas_engine.action_controller" do
      ActiveSupport.on_load :action_controller do
        helper EfirmasEngine::Engine.helpers
      end
    end

    initializer "efirmas_engine.load_migrations" do
      unless config.paths['db/migrate'].existent
        config.paths.add 'db/migrate', with: 'db/migrate'
      end
    end
  end
end