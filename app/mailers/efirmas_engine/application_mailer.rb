module EfirmasEngine
  require 'net/http'
  require 'uri'
  require 'json'

  class ApplicationMailer < ActionMailer::Base
    before_action :set_xouath2_access_token_from_credentials

    default from: -> { Rails.application.credentials.google.fetch(:email_user) }
    layout "mailer"

    private

    def set_xouath2_access_token_from_credentials
      cached_token = Rails.cache.read("google_mailer_access_token")

      access_token = if cached_token.present?
                      cached_token
                    else
                      fetch_new_google_access_token
                    end


      if access_token
        ActionMailer::Base.smtp_settings[:password] = access_token
      else
        Rails.logger.error "Error: No se pudo obtener el token de acceso de Google para el Mailer."
      end
    end

    def fetch_new_google_access_token
      creds = Rails.application.credentials.google
      uri = URI("https://accounts.google.com/o/oauth2/token")
      
      begin
        response = Net::HTTP.post_form(uri, {
          client_id:     creds.fetch(:mailer_client_id),
          client_secret: creds.fetch(:mailer_client_secret),
          refresh_token: creds.fetch(:mailer_refresh_token),
          grant_type:    "refresh_token"
        })

        if response.is_a?(Net::HTTPSuccess)
          token_data = JSON.parse(response.body)
          new_token = token_data["access_token"]
          expires_in = token_data["expires_in"].to_i - 60 

          Rails.cache.write("google_mailer_access_token", new_token, expires_in: expires_in.seconds)
          
          return new_token
        else
          Rails.logger.error "Error al refrescar token de Google Mailer: #{response.code} #{response.body}"
          return nil
        end
      rescue StandardError => e
        Rails.logger.error "Excepción al refrescar token de Google Mailer: #{e.message}"
        return nil
      end
    end
  end
end
