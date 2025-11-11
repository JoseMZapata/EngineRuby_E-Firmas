class CreateEfirmasEngineFiles < ActiveRecord::Migration[8.0]
  def change
    create_table :efirmas_engine_files do |t|
      t.string :nombre_archivo, null: false
      t.string :tipo_archivo
      t.integer :byte_size
      t.string :llave
      t.integer :acuerdo_id, null: false
      t.timestamps
    end

    add_index :efirmas_engine_files, :acuerdo_id
    add_foreign_key :efirmas_engine_files, :efirmas_engine_acuerdos, column: :acuerdo_id
  end
end