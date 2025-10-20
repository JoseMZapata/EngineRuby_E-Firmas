# This migration comes from moca (originally 20250303202600)
class CreateMocaPeople < ActiveRecord::Migration[8.0]
  def change
    create_table :moca_people do |t|
      t.string :first_name
      t.string :first_last_name
      t.string :second_last_name
      t.string :email
      t.date :birth_date
      t.integer :gender, limit: 1
      t.string :curp
      t.datetime :last_login
      t.integer :status, limit: 1

      t.belongs_to :personifiable, polymorphic: true

      t.timestamps
    end
  end
end
