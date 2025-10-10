class CreateAcuerdoFirmas < ActiveRecord::Migration[8.0]
  def change
    create_table :acuerdo_firmas do |t|
      t.references :acuerdo, null: false, foreign_key: true
      t.references :user, null: false, foreign_key: true
      t.references :firma, null: false, foreign_key: true
      t.timestamps
    end
  end
end
