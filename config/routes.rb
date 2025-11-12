EfirmasEngine::Engine.routes.draw do
  resources :firmas, only: [:new, :create, :show]
  
  resources :acuerdos do
    get :archivo, on: :member
    resources :comentario_acuerdos, only: [:create]
  end
  
  root to: "acuerdos#index"
end