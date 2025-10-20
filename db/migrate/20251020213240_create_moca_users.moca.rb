# This migration comes from moca (originally 20250829012707)
class CreateMocaUsers < ActiveRecord::Migration[8.0]
  def change
    create_table :moca_users do |t|
      t.bigint      :person_id
      t.string      :email
      t.string      :password_digest
      t.integer     :status, limit: 1
      t.datetime    :last_login
      t.belongs_to  :personifiable, polymorphic: true
      t.timestamps
    end
  end
end
