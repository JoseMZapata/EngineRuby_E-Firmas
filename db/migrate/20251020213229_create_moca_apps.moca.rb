# This migration comes from moca (originally 20250308210041)
class CreateMocaApps < ActiveRecord::Migration[8.0]
  def change
    create_table :moca_apps do |t|
      t.string :name
      t.string :full_name
      t.string :url
      t.string :description
      t.boolean :is_active

      t.timestamps
    end
  end
end
