# This migration comes from moca (originally 20250303202444)
class CreateMocaStates < ActiveRecord::Migration[8.0]
  def change
    create_table :moca_states do |t|
      t.string :name, limit: 50
      t.string :code, limit: 5
      t.integer :federal_entity, limit: 1

      t.timestamps
    end
  end
end
