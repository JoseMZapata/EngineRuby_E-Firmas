# This file should ensure the existence of records required to run the application in every environment (production,
# development, test). The code here should be idempotent so that it can be executed at any point in every environment.
# The data can then be loaded with the bin/rails db:seed command (or created alongside the database with db:setup).
#
# Example:
#
#   ["Action", "Comedy", "Drama", "Horror"].each do |genre_name|
#     MovieGenre.find_or_create_by!(name: genre_name)
#   end
#
# Seed initial users for the User model
User.create!(
  [
    { id: 1, name: 'ISMAEL HERNANDEZ LANDEROS', curp: 'HELI860902HDGRNS01' },
    { id: 2, name: 'JOSE MANUEL ZAPATA RANGEL', curp: 'ZARM040223HDGPNNA9' }
  ]
)
