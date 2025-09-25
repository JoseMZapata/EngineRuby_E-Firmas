class CreateFirmas < ActiveRecord::Migration[8.0]
  def change
    create_table :firmas do |t|
      t.text :public_key
      t.text :private_key
      t.string :password
      t.string :file

      t.timestamps
    end
  end
end
