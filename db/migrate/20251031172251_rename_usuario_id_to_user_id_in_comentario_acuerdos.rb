class RenameUsuarioIdToUserIdInComentarioAcuerdos < ActiveRecord::Migration[8.0]
  def change
    rename_column :comentario_acuerdos, :usuario_id, :user_id
  end
end