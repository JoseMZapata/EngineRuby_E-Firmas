class CreateEfirmasEngineFirmas < ActiveRecord::Migration[8.0]
  def change
    create_table :efirmas_engine_firmas do |t|
      t.text :firma_base64
      t.integer :user_id, null: false
      t.integer :file_id, null: false
      t.string :serie_certificado
      t.timestamps
    end

    add_index :efirmas_engine_firmas, :user_id
    add_index :efirmas_engine_firmas, :file_id
    add_foreign_key :efirmas_engine_firmas, :efirmas_engine_files, column: :file_id
    # NO agregamos foreign_key para user_id porque el modelo User es externo
  end
end