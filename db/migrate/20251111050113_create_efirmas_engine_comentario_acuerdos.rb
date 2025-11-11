class CreateEfirmasEngineComentarioAcuerdos < ActiveRecord::Migration[8.0]
  def change
    create_table :efirmas_engine_comentario_acuerdos do |t|
      t.integer :acuerdo_id, null: false
      t.integer :usuario_id, null: false
      t.string :motivo, null: false
      t.text :comentario, null: false
      t.timestamps
    end

    add_index :efirmas_engine_comentario_acuerdos, :acuerdo_id
    add_index :efirmas_engine_comentario_acuerdos, :usuario_id
    
    add_foreign_key :efirmas_engine_comentario_acuerdos, :efirmas_engine_acuerdos, column: :acuerdo_id
    # NO agregamos foreign_key para usuario_id porque el modelo User es externo
  end
end
