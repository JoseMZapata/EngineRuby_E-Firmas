# This migration comes from moca (originally 20250529234346)
class CreateMocaStudents < ActiveRecord::Migration[8.0]
  def change
    create_table :moca_students do |t|
      t.integer :program_id, limit: 1
      t.string  :identificator, limit: 20
      t.integer :consecutive
      t.string  :cvu
      t.integer :supervisor
      t.integer :co_supervisor
      t.integer :external_supervisor
      t.integer :student_time, limit: 1
      t.integer :scholarship_type, limit: 1
      t.string  :scholarship_number
      t.integer :department_id, limit: 1
      t.integer :location_id, limit: 1
      t.integer :campus_id
      t.string  :door
      t.integer :previous_institution
      t.string  :previous_degree_type
      t.string  :previous_degree_desc
      t.date    :previous_degree_start_date
      t.date    :previous_degree_end_date
      t.string  :previous_degree_license
      t.date    :start_date
      t.date    :end_date
      t.date    :inactive_date
      t.date    :graduation_date
      t.integer :status

      t.timestamps
    end
  end
end
