class UpdateFirmasFields < ActiveRecord::Migration[8.0]
  def change
    # Eliminar columnas antiguas
    remove_column :firmas, :public_key, :text
    remove_column :firmas, :private_key, :text
    remove_column :firmas, :password, :string
    remove_column :firmas, :file, :string

    # Agregar nuevas columnas
    add_column :firmas, :firma_base64, :text
    add_column :firmas, :personas_id, :integer
    add_column :firmas, :serie_certificado, :string
    add_column :firmas, :file_id, :integer
  end
end
