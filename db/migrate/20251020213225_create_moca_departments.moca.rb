# This migration comes from moca (originally 20250217231215)
class CreateMocaDepartments < ActiveRecord::Migration[8.0]
  def change
    create_table :moca_departments do |t|
      t.string :name, limit: 100
      t.string :short_name, limit: 100
      t.integer :person_id
      t.integer :department_id, limit: 2

      t.timestamps
    end
  end
end
