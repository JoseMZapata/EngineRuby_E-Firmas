Rails.application.routes.draw do
  resources :firmas, only: [:new, :create, :show]
  resources :acuerdos, only: [:new, :create, :show, :index, :edit] do
    get :archivo, on: :member
  end

end
