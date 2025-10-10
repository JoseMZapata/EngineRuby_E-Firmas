class CreateAcuerdos < ActiveRecord::Migration[8.0]
  def change
    create_table :acuerdos do |t|
      t.string :name, null: false
      t.references :usuario_creador, null: false, foreign_key: { to_table: :users }
      t.timestamps
    end
  end
end
