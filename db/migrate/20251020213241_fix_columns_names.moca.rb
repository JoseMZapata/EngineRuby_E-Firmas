# This migration comes from moca (originally 20250903202322)
class FixColumnsNames < ActiveRecord::Migration[8.0]
  def change
    rename_column :moca_departments, :person_id, :user_id
    rename_column :moca_app_user_roles, :person_id, :user_id
  end
end
