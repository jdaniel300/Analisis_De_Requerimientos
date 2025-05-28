!Importante!
Al inicializar por primera vez el proyecto en docker se utiliza docker-compose.yml
esto levanta las imagenes simultaneamente tanto como la base de datos y el proyecto 

- docker-compose -f docker-compose.yml up

Para bajar el proyecto de docker se utiliza (OJO esto elimina la imagen de base de datos, por lo tanto todo el contenido en tablas tambien)

- docker-compose down

Si se realizan cambios en el proyecto AccionSocial.web y para verlos reflejados en el contenedor ejecutar:

- docker-compose build
- docker-compose up -d accionsocial.web
