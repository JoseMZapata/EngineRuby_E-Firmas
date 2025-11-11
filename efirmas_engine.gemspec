require_relative "lib/efirmas_engine/version"

Gem::Specification.new do |spec|
  spec.name        = "efirmas_engine"
  spec.version     = EfirmasEngine::VERSION
  spec.authors     = [ "JoseMZapata" ]
  spec.email       = [ "josemanuelzapaatarangel@gmail.com" ]
  spec.homepage    = "https://github.com/JoseMZapata/EngineRuby_E-Firmas"
  spec.summary     = "Engine para gestión de e-firmas"
  spec.description = "Sistema de firmas electrónicas reutilizable para aplicaciones Rails"
  spec.license     = "MIT"

  # Prevent pushing this gem to RubyGems.org. To allow pushes either set the "allowed_push_host"
  # to allow pushing to a single host or delete this section to allow pushing to any host.
  spec.metadata["allowed_push_host"] = "TODO: Set to 'http://mygemserver.com'"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/JoseMZapata/EngineRuby_E-Firmas"
  spec.metadata["changelog_uri"] = "https://github.com/JoseMZapata/EngineRuby_E-Firmas/blob/main/efirmas_engine/CHANGELOG.md"

  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    Dir["{app,config,db,lib}/**/*", "MIT-LICENSE", "Rakefile", "README.md"]
  end

  spec.add_dependency "rails", ">= 8.0.2.1"
end
