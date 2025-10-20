require "test_helper"

class InvitacionFirmaMailerTest < ActionMailer::TestCase
  test "notificar_firmante" do
    mail = InvitacionFirmaMailer.notificar_firmante
    assert_equal "Notificar firmante", mail.subject
    assert_equal [ "to@example.org" ], mail.to
    assert_equal [ "from@example.com" ], mail.from
    assert_match "Hi", mail.body.encoded
  end
end
