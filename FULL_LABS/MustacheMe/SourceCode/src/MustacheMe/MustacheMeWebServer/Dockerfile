FROM awsbootcamp/mustachemebase

COPY api-static/ /var/www/forklift

RUN cd /var/www/forklift && \
	ln -s $PWD/nginx/nginx.conf /etc/nginx/conf.d

# Disable daemon mode for nginx
RUN echo "daemon off;" >> /etc/nginx/nginx.conf

EXPOSE 8000

# Set working directory
WORKDIR /var/www/forklift/

# Set the default command to execute when creating a new container
CMD service nginx start
