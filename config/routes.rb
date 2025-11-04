Rails.application.routes.draw do
  resources :firmas, only: [:new, :create, :show]
  resources :acuerdos, only: [:new, :create, :show, :index, :edit, :update] do
    get :archivo, on: :member
    resources :comentario_acuerdos, only: [:create]
  end
end
