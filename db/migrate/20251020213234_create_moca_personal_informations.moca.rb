# This migration comes from moca (originally 20250515192935)
class CreateMocaPersonalInformations < ActiveRecord::Migration[8.0]
  def change
    create_table :moca_personal_informations do |t|
      t.bigint :person_id
      t.string :address
      t.string :neighborhood
      t.string :city
      t.string :zip
      t.integer :state_id, limit: 1
      t.string :phone
      t.string :mobile_phone
      t.string :email
      t.integer :country_of_birth, limit: 2
      t.string :city_of_birth
      t.string :state_of_birth
      t.string :rfc
      t.string :ssn
      t.string :ine
      t.string :passport
      t.integer :marital_status, limit: 1
      t.integer :blood_type, limit: 1

      t.timestamps
    end
  end
end
