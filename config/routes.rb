Rails.application.routes.draw do
  resources :firmas, only: [:new, :create, :show]
end
