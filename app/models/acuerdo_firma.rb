class AcuerdoFirma < ApplicationRecord
  belongs_to :acuerdo
  belongs_to :user
  belongs_to :firma
end
