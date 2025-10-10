class FileRecord < ApplicationRecord
  self.table_name = 'files'
  belongs_to :acuerdo
  has_many :firmas, foreign_key: 'file_id'
end
