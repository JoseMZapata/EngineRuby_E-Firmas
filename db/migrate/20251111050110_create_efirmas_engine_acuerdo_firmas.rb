class CreateEfirmasEngineAcuerdoFirmas < ActiveRecord::Migration[8.0]
  def change
    create_table :efirmas_engine_acuerdo_firmas do |t|
      t.integer :acuerdo_id, null: false
      t.integer :user_id, null: false
      t.integer :firma_id
      t.string :status, default: "pendiente"
      t.timestamps
    end

    add_index :efirmas_engine_acuerdo_firmas, :acuerdo_id
    add_index :efirmas_engine_acuerdo_firmas, :user_id
    add_index :efirmas_engine_acuerdo_firmas, :firma_id
    
    add_foreign_key :efirmas_engine_acuerdo_firmas, :efirmas_engine_acuerdos, column: :acuerdo_id
    add_foreign_key :efirmas_engine_acuerdo_firmas, :efirmas_engine_firmas, column: :firma_id
    # NO agregamos foreign_key para user_id porque el modelo User es externo
  end
end