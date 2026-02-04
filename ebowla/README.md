### Usage

1. Download dockerimage file.

2. In the same folder generate docker image:

Linux -> `docker build --no-cache -t ebowla-legacy .`
MacOS -> `docker buildx build --platform linux/amd64 --no-cache -t ebowla-legacy .` (will take time)


3. Check curren docker images:

`docker images`

4. Run container

`docker run -it ebowla-legacy`




