# EfirmasEngine

Sistema de firmas electrónicas reutilizable para aplicaciones Rails.

## Características

- ✅ Creación de acuerdos con documentos adjuntos
- ✅ Firma digital con certificados .cer y .key
- ✅ Sistema de comentarios para reportar problemas
- ✅ Notificaciones por correo electrónico
- ✅ Edición de acuerdos con reinicio de firmas
- ✅ Compatible con cualquier modelo de usuario

## Instalación

Agrega esta línea al Gemfile de tu aplicación:
```ruby
gem 'efirmas_engine', git: 'https://github.com/JoseMZapata/EngineRuby_E-Firmas', glob: 'efirmas_engine/*.gemspec'
```

Luego ejecuta:
```bash
bundle install
```

Instala las migraciones:
```bash
rails efirmas_engine:install:migrations
rails db:migrate
```

## Configuración

Crea un inicializador en `config/initializers/efirmas_engine.rb`:
```ruby
EfirmasEngine.setup do |config|
  # Configura el nombre de tu modelo de usuario
  config.user_class = "User"  # o "Moca::User", etc.
  
  # Método para obtener el usuario actual
  config.current_user_method = :current_user
end
```

## Montaje

En tu `config/routes.rb`:
```ruby
Rails.application.routes.draw do
  mount EfirmasEngine::Engine, at: "/efirmas"
  
  # Tus otras rutas...
end
```

Ahora puedes acceder a:
- `/efirmas` - Listado de acuerdos
- `/efirmas/acuerdos/new` - Crear nuevo acuerdo
- `/efirmas/firmas/new` - Firmar acuerdo

## Requisitos

Tu aplicación host debe tener:

1. **Un modelo de usuario** con los campos:
   - `name` (o `nombre`)
   - `email`
   - Método `find_by_rfc(rfc)` para buscar usuarios por RFC (Y otros auxiliares que fueron puestos en el desarrollo del engine)
      ```ruby
      def to_h
        { id: id, name: name, curp: curp }
      end

      def self.find_by_rfc(curp)
        find_by(curp: curp)
      end

      def self.valid_rfc?(curp)
        exists?(curp: curp)
      end
      ```



## Uso

### Crear un acuerdo
```ruby
acuerdo = EfirmasEngine::Acuerdo.create!(
  name: "Contrato de trabajo",
  usuario_creador_id: current_user.id
)
```

### Configurar almacenamiento

Los archivos se guardan en `storage/efirmas_engine/`. Asegúrate de tener esta carpeta con permisos de escritura.

## Configuración de correos

Configura tu mailer en `config/environments/production.rb`:
```ruby
config.action_mailer.default_url_options = { host: 'tudominio.com' }
```


## Licencia

MIT License. Ver archivo MIT-LICENSE para más detalles.