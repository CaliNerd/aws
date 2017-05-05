This directory contains the Dockerfile to create the MustacheMe Web Server container

It depends on the mustacheme:base container

The mustacheme:webserver container is responsible for handling and servicing all request from the web pages.

It forwards all actions to their respective micro service containers.  

The following microservices containers are available:

mustacheme:info -> handles all /info and /cookie HTTP requests
mustacheme:processor -> handles all /images* HTTP requests

Contains only all of the HTML files to run the website.

All python (serv.py), cv2, haarcascades, process_img, uwsgi directories are missing from this distribution.

INSTRUCTIONS:
1. CD MustacheMeWebServer
2. docker build -t mustacheme:webserver .
3. docker run --name mustacheme -d -p 8000:8000 mustacheme:webserver
