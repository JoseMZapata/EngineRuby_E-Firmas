class CreateComentarioAcuerdos < ActiveRecord::Migration[8.0]
  def change
    create_table :comentario_acuerdos do |t|
      t.integer :acuerdo_id, null: false
      t.integer :user_id, null: false
      t.string :motivo, null: false
      t.text :comentario, null: false

      t.timestamps
    end

    add_index :comentario_acuerdos, :acuerdo_id
    add_index :comentario_acuerdos, :user_id
    add_foreign_key :comentario_acuerdos, :acuerdos
    add_foreign_key :comentario_acuerdos, :users
  end
end