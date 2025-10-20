# This migration comes from moca (originally 20250303202427)
class CreateMocaCountries < ActiveRecord::Migration[8.0]
  def change
    create_table :moca_countries do |t|
      t.string :name, limit: 50
      t.string :name_en, limit: 50
      t.string :code, limit: 2
      t.string :code3, limit: 3
      t.string :telephone_code, limit: 3

      t.timestamps
    end
  end
end
