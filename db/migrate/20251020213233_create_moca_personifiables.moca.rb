# This migration comes from moca (originally 20250514222929)
class CreateMocaPersonifiables < ActiveRecord::Migration[8.0]
  def change
    create_table :moca_personifiables do |t|
      t.bigint :person_id
      t.belongs_to :personifiable, polymorphic: true
      t.timestamps
    end
  end
end
