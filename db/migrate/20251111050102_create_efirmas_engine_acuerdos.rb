class CreateEfirmasEngineAcuerdos < ActiveRecord::Migration[8.0]
  def change
    create_table :efirmas_engine_acuerdos do |t|
      t.string :name, null: false
      t.integer :usuario_creador_id, null: false
      t.timestamps
    end

    add_index :efirmas_engine_acuerdos, :usuario_creador_id
  end
end