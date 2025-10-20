# This migration comes from moca (originally 20250308210334)
class CreateMocaAppRoles < ActiveRecord::Migration[8.0]
  def change
    create_table :moca_app_roles do |t|
      t.integer :app_id
      t.string :identificator
      t.string :name
      t.string :description
      
      t.timestamps
    end
  end
end
