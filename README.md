# Bottle Gitea Authentication Example Application

This repository contains the corresponding source code 
for the [Cope Systems blog post here.](https://blog.copesystems.com/2019/11/25/simple-nginx-authentication-hack-with-bottle/)

This sample application allows users to make use of
NGINX's subrequest authentication facilities to use a Gitea SQLite
database for user authentication in NGINX itself, allowing users
to protect other pages while maintaining easy means
of user administration (using Gitea itself). 