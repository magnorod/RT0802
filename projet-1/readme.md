apt-get install docker.io docker-compose -y

build -t alpine-rt802 .

docker-compose up -d
