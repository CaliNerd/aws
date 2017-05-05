This directory contains the Dockerfile to create the MustacheMe Info container

It depends on the mustacheme:base container

The mustacheme:processor container is responsible for handling and servicing all request from the web pages related to the following urls:
/info
/cookie

All html files are not part of this distribution.

INSTRUCTIONS:
1. CD MustacheMeInfo
2. docker build -t mustacheme:info .
3. docker run --name info -d -p 8092:8092 mustacheme:info



