# This migration comes from moca (originally 20250522230403)
class CreateMocaSecihtiResearchers < ActiveRecord::Migration[8.0]
  def change
    create_table :moca_secihti_researchers do |t|
      t.integer :department_id, limit: 1
      t.integer :location_id, limit: 1
      t.string  :door
      t.integer :boss_id
      t.string :cvu
      t.integer :sni, limit: 1
      t.string :sni_number
      t.date :start_date
      t.date :end_date
      t.integer :status

      t.timestamps
    end
  end
end
