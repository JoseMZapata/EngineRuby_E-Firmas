class FirmasController < ApplicationController
    def new 
        @firma = Firma.new
    end

    def create 
        @firma = Firma.new(firma_params)
        if @firma.save 
            redirect_to @firma, notice: 'Nueva firma realizada'
        else
            render :new
        end
    end

    private

    def firma_params
        params.require(:firma).permit(:public_key, :private_key, :password, :file)
    end
end
