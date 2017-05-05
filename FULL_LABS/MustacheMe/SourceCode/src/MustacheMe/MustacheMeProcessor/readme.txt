This directory contains the Dockerfile to create the MustacheMe Image Processor container

It depends on the mustacheme:base container

The mustacheme:processor container is responsible for handling and servicing all request from the web pages related to images.

All html files are not part of this distribution.

INSTRUCTIONS:
1. CD MustacheMeProcessor
2. docker build -t mustacheme:processor .
3. docker run --name processor -d -p 8082:8082 mustacheme:processor

