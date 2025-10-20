class ChangeAcuerdoFirmasForInvitations < ActiveRecord::Migration[8.0]
  def change
    add_column :acuerdo_firmas, :status, :string, default: 'pendiente'

    change_column_null :acuerdo_firmas, :firma_id, true
  end
end
