class CreateFirmas < ActiveRecord::Migration[8.0]
  def change
    create_table :firmas do |t|
      t.text :firma_base64
      t.string :file
      t.references :user, null: false, foreign_key: true
      t.references :file, null: false, foreign_key: { to_table: :files }
      t.string :serie_certificado
      t.timestamps
    end
  end
end
