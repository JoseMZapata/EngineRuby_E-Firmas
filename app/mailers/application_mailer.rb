class ApplicationMailer < ActionMailer::Base
  before_action :set_xouath2_access_token
  default from: "example.com"
  layout "mailer"
end
