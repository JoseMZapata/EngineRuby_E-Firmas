# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[8.0].define(version: 2025_10_09_235900) do
  create_table "acuerdo_firmas", force: :cascade do |t|
    t.integer "acuerdo_id", null: false
    t.integer "user_id", null: false
    t.integer "firma_id", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["acuerdo_id"], name: "index_acuerdo_firmas_on_acuerdo_id"
    t.index ["firma_id"], name: "index_acuerdo_firmas_on_firma_id"
    t.index ["user_id"], name: "index_acuerdo_firmas_on_user_id"
  end

  create_table "acuerdos", force: :cascade do |t|
    t.string "name", null: false
    t.integer "usuario_creador_id", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["usuario_creador_id"], name: "index_acuerdos_on_usuario_creador_id"
  end

  create_table "files", force: :cascade do |t|
    t.string "nombre_archivo", null: false
    t.string "tipo_archivo"
    t.integer "byte_size"
    t.string "llave"
    t.integer "acuerdo_id", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["acuerdo_id"], name: "index_files_on_acuerdo_id"
  end

  create_table "firmas", force: :cascade do |t|
    t.text "firma_base64"
    t.integer "user_id", null: false
    t.integer "file_id", null: false
    t.string "serie_certificado"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["file_id"], name: "index_firmas_on_file_id"
    t.index ["user_id"], name: "index_firmas_on_user_id"
  end

  create_table "users", force: :cascade do |t|
    t.string "name", null: false
    t.string "curp", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["curp"], name: "index_users_on_curp", unique: true
  end

  add_foreign_key "acuerdo_firmas", "acuerdos"
  add_foreign_key "acuerdo_firmas", "firmas"
  add_foreign_key "acuerdo_firmas", "users"
  add_foreign_key "acuerdos", "users", column: "usuario_creador_id"
  add_foreign_key "files", "acuerdos"
  add_foreign_key "firmas", "files"
  add_foreign_key "firmas", "users"
end
