class CreateFiles < ActiveRecord::Migration[8.0]
  def change
    create_table :files do |t|
      t.string :nombre_archivo, null: false
      t.string :tipo_archivo
      t.integer :byte_size
      t.string :llave
      t.references :acuerdo, null: false, foreign_key: true
      t.timestamps
    end
  end
end
