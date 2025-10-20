# This migration comes from moca (originally 20250403184913)
class CreateMocaEmployees < ActiveRecord::Migration[8.0]
  def change
    create_table :moca_employees do |t|
      t.integer :department_id, limit: 1
      t.integer :location_id, limit: 1
      t.string  :door
      t.string :job_title
      t.string :category
      t.string :regimen
      t.integer :boss_id
      t.date :start_date
      t.date :end_date
      t.string :netmultix_code
      t.string :cvu
      t.integer :sni, limit: 1
      t.string :sni_number
      t.integer :status
      
      t.timestamps
    end
  end
end
