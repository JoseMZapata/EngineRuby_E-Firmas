# This migration comes from moca (originally 20250217230444)
class CreateMocaLocations < ActiveRecord::Migration[8.0]
  def change
    create_table :moca_locations do |t|
      t.string :name, limit: 30
      t.string :code, limit: 6
      t.string :address, limit: 150
      t.string :neighborhood, limit: 50
      t.integer :state_id, limit: 1
      t.string :city, limit: 30
      t.string :county, limit: 30
      t.string :district, limit: 30
      t.string :zip, limit: 5

      t.timestamps
    end
  end
end
