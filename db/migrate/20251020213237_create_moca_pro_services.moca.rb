# This migration comes from moca (originally 20250529225251)
class CreateMocaProServices < ActiveRecord::Migration[8.0]
  def change
    create_table :moca_pro_services do |t|
      t.integer :department_id, limit: 1
      t.integer :location_id, limit: 1
      t.string  :door
      t.integer :responsible_id
      t.date    :start_date
      t.date    :end_date
      t.string  :notes
      t.integer :status

      t.timestamps
    end
  end
end
