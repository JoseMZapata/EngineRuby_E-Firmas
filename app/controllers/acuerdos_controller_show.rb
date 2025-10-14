class AcuerdosController < ApplicationController
  def show
    @acuerdo = Acuerdo.find(params[:id])
  end
end
