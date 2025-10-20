# This migration comes from moca (originally 20250308210549)
class CreateMocaAppUserRoles < ActiveRecord::Migration[8.0]
  def change
    create_table :moca_app_user_roles do |t|
      t.integer :app_id
      t.integer :person_id
      t.integer :app_role_id
      
      t.timestamps
    end
  end
end
