Generate docker image

Linux -> `docker build --no-cache -t ebowla-legacy .`
MacOS -> `docker buildx build --platform linux/amd64 --no-cache -t ebowla-legacy .` (will take time)


Check curren docker images:

`docker images`

Run container

`docker run -it ebowla-legacy`




