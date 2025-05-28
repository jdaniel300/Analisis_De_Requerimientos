Instalar docker desktop

Bajar la imagen en cmd con el comando 
docker pull mcr.microsoft.com/mssql/server

docker run --name "AccionDB" -e "ACCEP_EULA=Y" -e "MSSQL_SA_PASSWORD=AccionSocial123!" -p 1433:1433 -d mcr.microsoft.com/mssql/server:2022-latest

!Importante!
Al inicializar por primera vez el proyecto en docker se utiliza docker-compose.yml
esto levanta las imagenes simultaneamente tanto como la base de datos y el proyecto 

- docker-compose -f docker-compose.yml up

Para bajar el proyecto de docker se utiliza (OJO esto elimina la imagen de base de datos, por lo tanto todo el contenido en tablas tambien)

- docker-compose down

Si se realizan cambios en el proyecto AccionSocial.web y para verlos reflejados en el contenedor ejecutar:

- docker-compose build
- docker-compose up -d accionsocial.web
