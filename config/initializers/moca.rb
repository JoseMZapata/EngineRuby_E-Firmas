# config/initializers/moca.rb

require 'mail'
require 'net/imap'
require 'net/smtp'

Rails.application.config.after_initialize do
  ActionMailer::Base.smtp_settings = {
    address:              'smtp.gmail.com',
    port:                 587,
    domain:               'cimav.edu.mx',
    authentication:       :xoauth2,
    user_name:            ENV['EMAIL_USER'],
    enable_starttls_auto: true,
    oauth2_token: lambda {
      client_id = ENV['MAILER_CLIENT_ID']
      client_secret = ENV['MAILER_CLIENT_SECRET']
      refresh_token = ENV['MAILER_REFRESH_TOKEN']

      require 'googleauth'
      authorizer = Google::Auth::UserRefreshCredentials.new(
        client_id: client_id,
        client_secret: client_secret,
        scope: ['https://mail.google.com/'],
        redirect_uri: 'urn:ietf:wg:oauth:2.0:oob',
        refresh_token: refresh_token
      )
      authorizer.fetch_access_token!['access_token']
    }.call
  }

  ActionMailer::Base.default_options = {
    from: ENV['EMAIL_USER']
  }
end
