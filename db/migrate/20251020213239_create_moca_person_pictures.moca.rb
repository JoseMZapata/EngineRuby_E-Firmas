# This migration comes from moca (originally 20250704174544)
class CreateMocaPersonPictures < ActiveRecord::Migration[8.0]
  def change
    create_table :moca_person_pictures do |t|
      t.bigint   :person_id
      t.string   :original_filename
      t.string   :filename

      t.timestamps
    end
  end
end
