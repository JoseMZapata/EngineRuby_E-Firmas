class RemoveFileFromFirmas < ActiveRecord::Migration[8.0]
  def change
    remove_column :firmas, :file, :string
  end
end
