Bajar el repositorio de GitHub

El proyecto base es AccionSocial, el que se llama PlataformaAccionSocial es prototipo


Instalar docker desktop

!Importante!
Al inicializar por primera vez el proyecto en la carpeta raiz abrimos la terminal donde se ejecutara el comando:

- docker-compose -f docker-compose.yml up
  
Esto levanta las imagenes simultaneamente tanto como la base de datos y el proyecto, una vez levantado utilizara la direccion:
http://localhost:8090/

Para bajar el proyecto de docker se utiliza

- docker-compose down

Si se realizan cambios en el proyecto AccionSocial.web y para verlos reflejados en el contenedor ejecutar:

- docker-compose build
- docker-compose up -d accionsocial.web

Para aplicar migraciones desde la carpeta raiz todo desde el api
dotnet ef migrations add "NombreMigracion" --project AccionSocialModels --startup-project AccionSocial.api
dotnet ef database update --project AccionSocialModels --startup-project AccionSocial.api
