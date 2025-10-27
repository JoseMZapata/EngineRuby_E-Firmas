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

ActiveRecord::Schema[8.0].define(version: 2025_10_20_213241) do
  create_table "acuerdo_firmas", force: :cascade do |t|
    t.integer "acuerdo_id", null: false
    t.integer "user_id", null: false
    t.integer "firma_id"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.string "status", default: "pendiente"
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

  create_table "moca_app_roles", force: :cascade do |t|
    t.integer "app_id"
    t.string "identificator"
    t.string "name"
    t.string "description"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "moca_app_user_roles", force: :cascade do |t|
    t.integer "app_id"
    t.integer "user_id"
    t.integer "app_role_id"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "moca_apps", force: :cascade do |t|
    t.string "name"
    t.string "full_name"
    t.string "url"
    t.string "description"
    t.boolean "is_active"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "moca_countries", force: :cascade do |t|
    t.string "name", limit: 50
    t.string "name_en", limit: 50
    t.string "code", limit: 2
    t.string "code3", limit: 3
    t.string "telephone_code", limit: 3
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "moca_departments", force: :cascade do |t|
    t.string "name", limit: 100
    t.string "short_name", limit: 100
    t.integer "user_id"
    t.integer "department_id", limit: 2
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "moca_employees", force: :cascade do |t|
    t.integer "department_id", limit: 1
    t.integer "location_id", limit: 1
    t.string "door"
    t.string "job_title"
    t.string "category"
    t.string "regimen"
    t.integer "boss_id"
    t.date "start_date"
    t.date "end_date"
    t.string "netmultix_code"
    t.string "cvu"
    t.integer "sni", limit: 1
    t.string "sni_number"
    t.integer "status"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "moca_locations", force: :cascade do |t|
    t.string "name", limit: 30
    t.string "code", limit: 6
    t.string "address", limit: 150
    t.string "neighborhood", limit: 50
    t.integer "state_id", limit: 1
    t.string "city", limit: 30
    t.string "county", limit: 30
    t.string "district", limit: 30
    t.string "zip", limit: 5
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "moca_people", force: :cascade do |t|
    t.string "first_name"
    t.string "first_last_name"
    t.string "second_last_name"
    t.string "email"
    t.date "birth_date"
    t.integer "gender", limit: 1
    t.string "curp"
    t.datetime "last_login"
    t.integer "status", limit: 1
    t.string "personifiable_type"
    t.integer "personifiable_id"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["personifiable_type", "personifiable_id"], name: "index_moca_people_on_personifiable"
  end

  create_table "moca_person_pictures", force: :cascade do |t|
    t.bigint "person_id"
    t.string "original_filename"
    t.string "filename"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "moca_personal_informations", force: :cascade do |t|
    t.bigint "person_id"
    t.string "address"
    t.string "neighborhood"
    t.string "city"
    t.string "zip"
    t.integer "state_id", limit: 1
    t.string "phone"
    t.string "mobile_phone"
    t.string "email"
    t.integer "country_of_birth", limit: 2
    t.string "city_of_birth"
    t.string "state_of_birth"
    t.string "rfc"
    t.string "ssn"
    t.string "ine"
    t.string "passport"
    t.integer "marital_status", limit: 1
    t.integer "blood_type", limit: 1
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "moca_personifiables", force: :cascade do |t|
    t.bigint "person_id"
    t.string "personifiable_type"
    t.integer "personifiable_id"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["personifiable_type", "personifiable_id"], name: "index_moca_personifiables_on_personifiable"
  end

  create_table "moca_pro_services", force: :cascade do |t|
    t.integer "department_id", limit: 1
    t.integer "location_id", limit: 1
    t.string "door"
    t.integer "responsible_id"
    t.date "start_date"
    t.date "end_date"
    t.string "notes"
    t.integer "status"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "moca_retireds", force: :cascade do |t|
    t.integer "department_id", limit: 1
    t.integer "location_id", limit: 1
    t.string "door"
    t.integer "responsible_id"
    t.string "cvu"
    t.integer "sni", limit: 1
    t.string "sni_number"
    t.date "start_date"
    t.date "end_date"
    t.integer "status"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "moca_secihti_researchers", force: :cascade do |t|
    t.integer "department_id", limit: 1
    t.integer "location_id", limit: 1
    t.string "door"
    t.integer "boss_id"
    t.string "cvu"
    t.integer "sni", limit: 1
    t.string "sni_number"
    t.date "start_date"
    t.date "end_date"
    t.integer "status"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "moca_states", force: :cascade do |t|
    t.string "name", limit: 50
    t.string "code", limit: 5
    t.integer "federal_entity", limit: 1
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "moca_students", force: :cascade do |t|
    t.integer "program_id", limit: 1
    t.string "identificator", limit: 20
    t.integer "consecutive"
    t.string "cvu"
    t.integer "supervisor"
    t.integer "co_supervisor"
    t.integer "external_supervisor"
    t.integer "student_time", limit: 1
    t.integer "scholarship_type", limit: 1
    t.string "scholarship_number"
    t.integer "department_id", limit: 1
    t.integer "location_id", limit: 1
    t.integer "campus_id"
    t.string "door"
    t.integer "previous_institution"
    t.string "previous_degree_type"
    t.string "previous_degree_desc"
    t.date "previous_degree_start_date"
    t.date "previous_degree_end_date"
    t.string "previous_degree_license"
    t.date "start_date"
    t.date "end_date"
    t.date "inactive_date"
    t.date "graduation_date"
    t.integer "status"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "moca_users", force: :cascade do |t|
    t.bigint "person_id"
    t.string "email"
    t.string "password_digest"
    t.integer "status", limit: 1
    t.datetime "last_login"
    t.string "personifiable_type"
    t.integer "personifiable_id"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["personifiable_type", "personifiable_id"], name: "index_moca_users_on_personifiable"
  end

  create_table "users", force: :cascade do |t|
    t.string "name", null: false
    t.string "curp", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.string "email"
    t.index ["curp"], name: "index_users_on_curp", unique: true
  end

  add_foreign_key "acuerdos", "users", column: "usuario_creador_id"
  add_foreign_key "files", "acuerdos"
  add_foreign_key "firmas", "files"
  add_foreign_key "firmas", "users"
end
