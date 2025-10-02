class CreateFirmas < ActiveRecord::Migration[8.0]
  def change
    create_table :firmas do |t|
      t.text :firma_base64
      t.integer :personas_id
      t.string :serie_certificado
      t.integer :file_id

      t.timestamps
    end
  end
end
